#include <kvdb/kvdb.hpp>

#include <shared_mutex>
#include <unordered_map>

#include <fmt/format.h>
#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <rocksdb/slice.h>
#include <rocksdb/utilities/optimistic_transaction_db.h>
#include <rocksdb/utilities/transaction.h>

#include <logging/logging.hpp>

#include <iostream>

static const struct Option
{
    rocksdb::ReadOptions read;
    rocksdb::WriteOptions write;
    rocksdb::DBOptions open;
    rocksdb::ColumnFamilyOptions CF;
    rocksdb::OptimisticTransactionOptions TX;
} kOptions;

struct KVDB::Impl
{
    enum class State
    {
        Open,
        Closed,
        Locked,
        Error,
        Invalid,
    };

    Impl(const std::string& dbName, const std::string& folder)
        : m_name(dbName)
        , m_txDb(nullptr)
        , m_db(nullptr)
        , m_state(State::Invalid)
        , m_shouldCleanupFiles(false)
    {
        // If path doesn't ends with "/" will cause undesired behavior
        if ('/' != folder.back())
        {
            m_path = folder + "/" + dbName;
        }
        else
        {
            m_path = folder + dbName;
        }

        WAZUH_ASSERT_MSG(!m_name.empty(),
                         "Engine KVDB: Trying to create a database with an empty name.");
        WAZUH_ASSERT_MSG(
            !m_path.empty(),
            "Engine KVDB: Trying to create database \"{}\" on an empty path.",
            m_name);
    }

    CreationStatus init(bool createIfMissing, bool errorIfExists)
    {
        if (errorIfExists && m_state != State::Invalid)
        {
            // Created previously
            return CreationStatus::ErrorDatabaseAlreadyExists;
        }
        else if (!errorIfExists && m_state == State::Open)
        {
            // Already initialized
            return CreationStatus::OkInitialized;
        }

        std::unique_lock lk(m_mtx);
        std::vector<std::string> cfNames;
        auto s = rocksdb::DB::ListColumnFamilies(kOptions.open, m_path, &cfNames);
        if (s.ok())
        {
            for (auto name : cfNames)
            {
                m_CFDescriptors.push_back(
                    rocksdb::ColumnFamilyDescriptor(name, kOptions.CF));
            }
        }
        else
        {
            m_CFDescriptors.push_back(
                rocksdb::ColumnFamilyDescriptor(DEFAULT_CF_NAME, kOptions.CF));
        }

        rocksdb::Options dbOptions;
        dbOptions.OptimizeLevelStyleCompaction();
        dbOptions.OptimizeForSmallDb();
        dbOptions.create_if_missing = createIfMissing;
        dbOptions.error_if_exists = errorIfExists;

        rocksdb::OptimisticTransactionDB* txdb;
        std::vector<rocksdb::ColumnFamilyHandle*> cfHandles;
        s = rocksdb::OptimisticTransactionDB::Open(
            dbOptions, m_path, m_CFDescriptors, &cfHandles, &txdb);
        if (!s.ok())
        {
            WAZUH_LOG_WARN(
                "Engine KVDB: Database \"{}\": File could not be created: \"{}\"",
                m_name,
                s.ToString());

            m_state = State::Error;
            const std::string errorString {s.getState()};
            // TODO: there's no flag or function that returns this error but the message
            // itself
            if (errorString.find("exists (error_if_exists is true)") != std::string::npos)
            {
                return CreationStatus::ErrorDatabaseAlreadyExists;
            }

            if (s.IsIOError())
            {
                // this could be covering other cases too.
                return CreationStatus::ErrorDatabaseBusy;
            }

            if (s.IsInvalidArgument() && !createIfMissing)
            {
                // TODO: Investigate the reason of this:
                // RocksDB creates a database even if the option create_if_missing is
                // false. The open operation fails, but the database is created
                // anyway.
                rocksdb::DestroyDB(m_path, rocksdb::Options(), m_CFDescriptors);
            }
            return CreationStatus::ErrorUnknown;
        }

        for (auto handle : cfHandles)
        {
            m_CFHandlesMap[handle->GetName()] = handle;
        }

        m_txDb = txdb;
        m_db = txdb->GetBaseDB();
        m_state = State::Open;
        return CreationStatus::OkCreated;
    }

    /**
     * @brief Check if the database is able to be used.
     *
     * @return true if the database can be used
     * @return false if the database can´t be used
     */
    bool isReady() const { return (m_state == State::Open); }

    bool isValid() const { return (m_state != State::Invalid); }

    const std::string& getName() const { return m_name; }

    rocksdb::ColumnFamilyHandle* getCFHandle(std::string const& colName)
    {
        WAZUH_ASSERT_MSG(!colName.empty(),
                         "Engine KVDB: Trying to get an empty column name.");

        // TODO: could not we open it here?
        if (m_state != State::Open)
        {
            WAZUH_LOG_ERROR("Engine KVDB: Database \"{}\" should be open to be executed.",
                            m_name);
            return nullptr;
        }

        auto cfh = m_CFHandlesMap.find(colName);
        if (cfh == m_CFHandlesMap.end())
        {
            // TODO: CF means config?
            WAZUH_LOG_ERROR("Engine KVDB: Database \"{}\": Failed to get CF \"{}\".",
                            m_name,
                            colName);
            return nullptr;
        }

        return cfh->second;
    }

    bool createColumn(const std::string& columnName)
    {
        if (columnName.empty())
        {
            return false;
        }

        std::unique_lock lk(m_mtx);
        auto cf = getCFHandle(columnName);
        if (cf)
        {
            // CF already present
            return false;
        }

        rocksdb::ColumnFamilyHandle* handler;
        rocksdb::Status s = m_db->CreateColumnFamily(kOptions.CF, columnName, &handler);
        if (s.ok())
        {
            m_CFDescriptors.push_back({columnName, {}});
            m_CFHandlesMap[handler->GetName()] = handler;
            return true;
        }

        WAZUH_LOG_ERROR("Engine KVDB: Database \"{}\": Couldn't create CF \"{}\": {}",
                        m_name,
                        columnName,
                        s.ToString());
        return false;
    }

    // TODO: all the default column names should be changed, one option is to
    // define a KVDB default CF in order to avoid using a deleteColumn or
    // cleanColumn without any argument
    bool deleteColumn(const std::string& columnName)
    {
        if (columnName.empty())
        {
            return false;
        }

        std::unique_lock lk(m_mtx);
        auto cf = getCFHandle(columnName);
        if (!cf)
        {
            return false;
        }

        if (!m_db->DropColumnFamily(cf).ok())
        {
            return false;
        }

        rocksdb::Status s = m_db->DestroyColumnFamilyHandle(cf);
        if (s.ok())
        {
            m_CFHandlesMap.erase(columnName);
            m_CFDescriptors.erase(std::remove_if(m_CFDescriptors.begin(),
                                                 m_CFDescriptors.end(),
                                                 [&](auto const& des)
                                                 { return des.name == columnName; }));

            return true;
        }

        return false;
    }

    bool cleanColumn(const std::string& columnName)
    {
        if (columnName.empty())
        {
            return false;
        }

        if (DEFAULT_CF_NAME == columnName)
        {
            rocksdb::Iterator* iter = m_db->NewIterator(kOptions.read);
            iter->SeekToFirst();
            while (iter->Valid())
            {
                deleteKey(iter->key().ToString(), columnName);
                iter->Next();
            };
            delete iter;
            return true;
        }
        else if (deleteColumn(columnName))
        {
            return createColumn(columnName);
        }
        return false;
    }

    bool
    write(const std::string& key, const std::string& value, const std::string& columnName)
    {
        if (key.empty() || columnName.empty())
        {
            return false;
        }

        std::shared_lock lk(m_mtx);
        auto cf = getCFHandle(columnName);
        if (!cf)
        {
            return false;
        }

        rocksdb::Status s = m_db->Put(kOptions.write, cf, key, value);
        if (!s.ok())
        {
            WAZUH_LOG_ERROR("Engine KVDB: Database \"{}\": Couldn't insert pair [{}:{}], "
                            "CF \"{}\": \"{}\"",
                            m_name,
                            key,
                            value,
                            columnName,
                            s.ToString());
            return false;
        }

        WAZUH_LOG_DEBUG("Engine KVDB: Database \"{}\": Pair [{}:{}] was successfully "
                        "inserted, CF \"{}\".",
                        m_name,
                        key,
                        value,
                        columnName);
        return true;
    }

    bool writeToTransaction(
        const std::vector<std::pair<std::string, std::string>>& pairsVector,
        const std::string& columnName)
    {
        if (columnName.empty())
        {
            return false;
        }

        std::shared_lock lk(m_mtx);
        auto cf = getCFHandle(columnName);
        if (!cf)
        {
            return false;
        }

        if (!pairsVector.size())
        {
            WAZUH_LOG_INFO("Engine KVDB: Database \"{}\": Transaction could not be "
                           "written, at least 1 element is required.",
                           m_name);
            return false;
        }

        rocksdb::Transaction* txn = m_txDb->BeginTransaction(kOptions.write);
        if (!txn)
        {
            WAZUH_LOG_ERROR(
                "Engine KVDB: Database \"{}\": Transaction could not be started.",
                m_name);
            return false;
        }

        // just delete the tx on scope exit
        _defer({ delete txn; });

        bool txnOk = true;
        for (auto const& [key, value] : pairsVector)
        {
            if (key.empty())
            {
                WAZUH_LOG_INFO("Engine KVDB: Database \"{}\": Pair [{}:{}] is discarded "
                               "because the key is empty.",
                               m_name,
                               key,
                               value);
                continue;
            }
            // Write a key-value in this transaction
            rocksdb::Status s = txn->Put(cf, key, value);
            if (!s.ok())
            {
                txnOk = false;
                WAZUH_LOG_ERROR("Engine KVDB: Database \"{}\": PUT operation could not "
                                "be executed in transaction: \"{}\"",
                                m_name,
                                s.ToString());
            }
        }

        rocksdb::Status s = txn->Commit();
        if (!s.ok())
        {
            txnOk = false;
            WAZUH_LOG_ERROR(
                "Engine KVDB: Database \"{}\": Transaction could not be commited: \"{}\"",
                m_name,
                s.ToString());
        }

        return txnOk;
    }

    bool hasKey(const std::string& key, const std::string& columnName)
    {
        if (key.empty() || columnName.empty())
        {
            return false;
        }

        std::shared_lock lk(m_mtx);
        auto cf = getCFHandle(columnName);
        if (!cf)
        {
            return false;
        }

        std::string value;
        // TODO We need to investigate this
        return m_db->KeyMayExist(kOptions.read, cf, key, &value);
    }

    std::optional<std::string> read(const std::string& key, const std::string& columnName)
    {
        if (key.empty() || columnName.empty())
        {
            return std::nullopt;
        }

        std::shared_lock lk(m_mtx);
        auto cf = getCFHandle(columnName);
        if (!cf)
        {
            return std::nullopt;
        }

        std::string result, value;
        rocksdb::Status s = m_db->Get(kOptions.read, cf, key, &value);
        if (!s.ok())
        {
            WAZUH_LOG_ERROR("Engine KVDB: Database \"{}\": Value from CF \"{}\" could "
                            "not be read: \"{}\"",
                            m_name,
                            columnName,
                            s.ToString());
            result.clear();
            return std::nullopt;
        }

        WAZUH_LOG_DEBUG("Engine KVDB: Database \"{}\": Value [{}:{}] successfully "
                        "obtained is discarded from CF \"{}\".",
                        m_name,
                        key,
                        value,
                        columnName);
        return value;
    }

    bool
    readPinned(const std::string& key, std::string& value, const std::string& columnName)
    {
        if (key.empty() || columnName.empty())
        {
            return false;
        }

        std::shared_lock lk(m_mtx);
        auto cf = getCFHandle(columnName);
        if (!cf)
        {
            return false;
        }

        rocksdb::PinnableSlice pinnable_val;
        rocksdb::Status s = m_db->Get(kOptions.read, cf, key, &pinnable_val);
        if (!s.ok())
        {
            WAZUH_LOG_ERROR(
                "Engine KVDB: Database \"{}\": Pinned value could not be read: \"{}\"",
                m_name,
                s.ToString());
            return false;
        }

        value = pinnable_val.ToString();
        WAZUH_LOG_DEBUG("Engine KVDB: Database \"{}\": Pinned value [{}:{}] successfully "
                        "read.",
                        m_name,
                        key,
                        value);
        return true;
    }

    bool deleteKey(const std::string& key, const std::string& columnName)
    {
        if (key.empty() || columnName.empty())
        {
            return false;
        }

        std::shared_lock lk(m_mtx);
        auto cf = getCFHandle(columnName);
        if (!cf)
        {
            return false;
        }

        // Sync to ensure that the proccess has instant effect
        auto WriteOptions = kOptions.write;
        WriteOptions.sync = true;
        rocksdb::Status s = m_db->Delete(WriteOptions, cf, key);
        if (!s.ok())
        {
            WAZUH_LOG_ERROR("Engine KVDB: Database \"{}\": Couldn't delete key \"{}\" "
                            "from CF \"{}\": \"{}\"",
                            m_name,
                            key,
                            columnName,
                            s.ToString());
            return false;
        }

        WAZUH_LOG_INFO("Engine KVDB: Database \"{}\": Key \"{}\" deleted.", m_name, key);
        return true;
    }

    bool close()
    {
        std::unique_lock lk(m_mtx);
        if (!m_txDb)
        {
            return true;
        }

        bool ret = true;
        rocksdb::Status s;
        for (auto const& it : m_CFHandlesMap)
        {
            s = m_db->DestroyColumnFamilyHandle(it.second);
            if (!s.ok())
            {
                WAZUH_LOG_ERROR("Engine KVDB: Database \"{}\": Family handler could not "
                                "be destroyed: \"{}\"",
                                m_name,
                                s.ToString());
                ret = false;
            }
        }

        m_CFHandlesMap.clear();

        s = m_db->Close();
        if (!s.ok())
        {
            WAZUH_LOG_ERROR(
                "Engine KVDB: Database \"{}\": Database could not be closed: \"{}\"",
                m_name,
                s.ToString());
            ret = false;
        }

        s = m_txDb->Close();
        if (!s.ok())
        {
            WAZUH_LOG_ERROR("Engine KVDB: Database \"{}\": Tansaction database could not "
                            "be closed: \"{}\"",
                            m_name,
                            s.ToString());
            ret = false;
        }

        delete m_txDb;
        m_txDb = nullptr;

        return ret;
    }

    /**
     * @brief Db destruction cleaning all files and data related to it
     *
     * @return true successfully destructed
     * @return false unsuccessfully destructed
     */
    bool deleteFile()
    {
        rocksdb::Status s =
            rocksdb::DestroyDB(m_path, rocksdb::Options(), m_CFDescriptors);
        if (!s.ok())
        {
            WAZUH_LOG_ERROR(
                "Engine KVDB: Database \"{}\": Database could not be destroyed: \"{}\"",
                m_name,
                s.ToString());
            m_state = State::Error;
            return false;
        }

        return true;
    }

    std::string_view dumpContent(json::Json& dump)
    {
        std::string errorMessage{}, jsonFill{};

        rocksdb::Iterator* iter = m_db->NewIterator(kOptions.read);
        iter->SeekToFirst();
        for (; iter->Valid(); iter->Next())
        {
            const auto value = iter->value().ToString();
            if (value.empty())
            {
                jsonFill = fmt::format("{{\"key\": \"{}\"}}", iter->key().ToString());
            }
            else
            {
                jsonFill = fmt::format("{{\"key\": \"{}\",\"value\": {}}}",
                                        iter->key().ToString(),value);
            }

            try
            {
                json::Json keyValueObject {jsonFill.c_str()};
                dump.appendJson(keyValueObject);
            }
            catch (const std::exception& e)
            {
                errorMessage =
                    fmt::format("Couldn't create and append object to array: {}", e.what());
            }
        }

        delete iter;
        return errorMessage;
    }

    std::string m_name;
    std::string m_path;
    bool m_shouldCleanupFiles;
    State m_state = State::Invalid;

    rocksdb::OptimisticTransactionDB* m_txDb;
    rocksdb::DB* m_db;
    std::vector<rocksdb::ColumnFamilyDescriptor> m_CFDescriptors;
    std::unordered_map<std::string, rocksdb::ColumnFamilyHandle*> m_CFHandlesMap;

    std::shared_mutex m_mtx;
};

KVDB::KVDB(const std::string& dbName, const std::string& folder)
    : mImpl(std::make_unique<KVDB::Impl>(dbName, folder))
{
}

KVDB::KVDB()
    : mImpl(std::make_unique<KVDB::Impl>("", ""))
{
}

KVDB::CreationStatus KVDB::init(bool createIfMissing, bool errorIfExists)
{
    return mImpl->init(createIfMissing, errorIfExists);
}

KVDB::~KVDB()
{
    mImpl->close();
    if (mImpl->m_shouldCleanupFiles)
    {
        mImpl->deleteFile();
    }
}

bool KVDB::close()
{
    return mImpl->close();
}

void KVDB::cleanupOnClose()
{
    mImpl->m_shouldCleanupFiles = true;
}

bool KVDB::writeKeyOnly(const std::string& key, const std::string& columnName)
{
    return mImpl->write(key, "", columnName);
}

bool KVDB::write(const std::string& key,
                 const std::string& value,
                 const std::string& columnName)
{
    return mImpl->write(key, value, columnName);
}

std::optional<std::string> KVDB::read(const std::string& key,
                                      const std::string& columnName)
{
    return mImpl->read(key, columnName);
}

bool KVDB::deleteKey(const std::string& key, const std::string& columnName)
{
    return mImpl->deleteKey(key, columnName);
}

bool KVDB::createColumn(const std::string& columnName)
{
    return mImpl->createColumn(columnName);
}

bool KVDB::deleteColumn(const std::string& columnName)
{
    return mImpl->deleteColumn(columnName);
}

bool KVDB::cleanColumn(const std::string& columnName)
{
    return mImpl->cleanColumn(columnName);
}

bool KVDB::writeToTransaction(
    const std::vector<std::pair<std::string, std::string>>& pairsVector,
    const std::string& columnName)
{
    return mImpl->writeToTransaction(pairsVector, columnName);
}

bool KVDB::hasKey(const std::string& key, const std::string& columnName)
{
    return mImpl->hasKey(key, columnName);
}

bool KVDB::readPinned(const std::string& key,
                      std::string& value,
                      const std::string& colName)
{
    return mImpl->readPinned(key, value, colName);
}

bool KVDB::isValid() const
{
    return mImpl->isValid();
}

bool KVDB::isReady() const
{
    return mImpl->isReady();
}

std::string_view KVDB::getName() const
{
    return mImpl->getName();
}

std::string_view KVDB::dumpContent(json::Json& dump)
{
    return mImpl->dumpContent(dump);
}

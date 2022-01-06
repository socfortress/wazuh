#ifndef __CATALOG_TEST_H__
#define __CATALOG_TEST_H__

#include <gtest/gtest.h>
#include <string>

#include "catalog/Catalog.hpp"
#include "Catalog_json_assets.hpp"
#include "rapidjson/error/en.h"

/**
 * @brief Fake storage driver
 * @details This class is used to test the Catalog class
 */
class fakeStorage : public StorageDriverInterface
{

    private:
        bool thwo_exception = false;
        bool return_empty = false;
        bool empty_schemas = false;
        bool malformed_schemas = false;

    public:
        fakeStorage() = default;
        ~fakeStorage() = default;

        std::vector<std::string_view> getAssetList(const AssetType type) override
        {
            std::vector<std::string_view> assets;

            if (!return_empty)
            {
                assets.push_back("asset_1");
                assets.push_back("asset_2");
                assets.push_back("asset_3");
            }

            return assets;
        }

        std::string getAsset(const AssetType type, std::string_view assetName) override
        {

            std::string asset;

            if (this->thwo_exception)
            {
                // #TODO throw exception
                ;;
            }

            switch (type)
            {
                case AssetType::Decoder:
                    if (assetName == "syslog2")
                    {
                        asset.append(yaml_decoder_valid);
                    }
                    else if (assetName == "syslog_malformed")
                    {
                        asset.append(yaml_decoder_malformed);
                    }
                    else if (assetName == "syslog_invalid_schema")
                    {
                        asset.append(yaml_decoder_invalid_schema);
                    }

                    break;

                case AssetType::Rule:
                    // #TODO add rule assets
                    ;;//raw_asset = rule_asset;
                    break;

                case AssetType::Output:
                    // #TODO add output assets
                    ;;//raw_asset = output_asset;
                    break;

                case AssetType::Filter:
                    // #TODO add filter assets
                    ;;//raw_asset = filter_asset;
                    break;

                case AssetType::Schemas:
                    if (this->malformed_schemas)
                    {
                        asset.append(schema_malformed);
                    }
                    else if (!this->empty_schemas)
                    {
                        asset.append(json_schema_decoder);
                    }

                    break;

                case AssetType::Environments:
                default:
                    // #TODO Error
                    break;
            }

            return asset;
        }

        // Methods to set configuration for the fake storage to test the Catalog class

        /** @brief Set the exception flag */
        void set_exception(bool exception)
        {
            this->thwo_exception = exception;
        }

        void set_empty_schemas(bool empty)
        {
            this->empty_schemas = empty;
        }

        void set_malformed_schemas(bool malformed_schemas)
        {
            this->malformed_schemas = malformed_schemas;
        }

};

#endif // __CATALOG_TEST_H__
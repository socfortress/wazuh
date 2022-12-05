/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

#include "headers/shared.h"
#include "agentlessd/agentlessd.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"

#define BUFFER_SIZE OS_MAXSTR - (OS_LOG_HEADER * 2)
#define STR_MORE_CHANGES "More changes..."
#define HOST "host"
#define SCRIPT "script"
#define AGTTYPE "agttype"
#define MSG "msg"
#define STR_HELPER(s) #s
#define STR(s) STR_HELPER(s)
#define ADT 1667392718

// internal use (static) not in agentlessd/agentlessd.h
int save_agentless_entry(const char *host, const char *script, const char *agttype);
int send_intcheck_msg(const char *script, const char *host, const char *msg);
int send_log_msg(const char *script, const char *host, const char *msg);
int gen_diff_alert(const char *host, const char *script, time_t alert_diff_time);

static int test_setup(void **state) {
    (void) state;
    test_mode = 1;
    return OS_SUCCESS;
}

static int test_teardown(void **state) {
    (void) state;
    test_mode = 0;
    return OS_SUCCESS;
}

void test_gen_diff_alert(void **state) {
    (void) state;

    expect_string(__wrap_fopen, path, DIFF_DIR "/" HOST "->" SCRIPT "/diff." STR(ADT));
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_fread(DIFF_DIR "/" HOST "->" SCRIPT "/diff." STR(ADT), BUFFER_SIZE);

    expect_SendMSG_call("ossec: agentless: Change detected:\n" STR_MORE_CHANGES, 
                "(" SCRIPT ") " HOST "->wazuh-agentlessd",
                LOCALFILE_MQ, 0);

    // save_agentless_entry() call
    expect_string(__wrap_fopen, path, AGENTLESS_ENTRYDIR "/(" SCRIPT ") " HOST);
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 2);

    expect_any(__wrap_fprintf, __stream);
    expect_string(__wrap_fprintf, formatted_msg, "type: diff\n");
    will_return(__wrap_fprintf, 0);

    expect_fclose((FILE *)2, 0);

    // save_agentless_entry() call
    expect_fclose((FILE *)1, 0);

    int rc = gen_diff_alert(HOST, SCRIPT, ADT);
    assert_int_equal(rc, 0);
}

void test_send_log_msg_ok(void **state) {
    (void) state;

    expect_string(__wrap_SendMSG, message, MSG);
    expect_string(__wrap_SendMSG, locmsg, "(" SCRIPT ") " HOST "->" SYSCHECK);
    expect_any(__wrap_SendMSG, loc);
    will_return(__wrap_SendMSG, 0);

    int rc = send_log_msg(SCRIPT, HOST, MSG);
    assert_int_equal(rc, 0);
}

void test_send_log_msg_wrong_sm(void **state) {
    (void) state;

    // message can´t sent
    expect_SendMSG_call(MSG, "(" SCRIPT ") " HOST "->" SYSCHECK,
                LOCALFILE_MQ, -1);
    
    expect_string(__wrap__merror, formatted_msg, QUEUE_SEND);
    expect_StartMQ_call(DEFAULTQUEUE, WRITE, 0);

    // try again... message can´t sent
    expect_SendMSG_call(MSG, "(" SCRIPT ") " HOST "->" SYSCHECK,
                LOCALFILE_MQ, -1);

    int rc = send_log_msg(SCRIPT, HOST, MSG);
    // anyway it'll be zero
    assert_int_equal(rc, 0);
}

void test_send_log_msg_fatal_exit(void **state) {
    (void) state;

    // message can´t sent
    expect_SendMSG_call(MSG, "(" SCRIPT ") " HOST "->" SYSCHECK,
                LOCALFILE_MQ, -1);
    
    expect_string(__wrap__merror, formatted_msg, QUEUE_SEND);
    expect_StartMQ_call(DEFAULTQUEUE, WRITE, -1);

    // enough space ever
    char msg[sizeof(QUEUE_FATAL) + sizeof(DEFAULTQUEUE)];
    snprintf(msg, sizeof(msg), QUEUE_FATAL, DEFAULTQUEUE);
    expect_string(__wrap__merror_exit, formatted_msg, msg);

    expect_assert_failure(send_log_msg(SCRIPT, HOST, MSG));
}

void test_send_intcheck_msg_ok(void **state) {
    (void) state;

    expect_string(__wrap_SendMSG, message, MSG);
    expect_string(__wrap_SendMSG, locmsg, "(" SCRIPT ") " HOST "->" SYSCHECK);
    expect_any(__wrap_SendMSG, loc);
    will_return(__wrap_SendMSG, 0);

    int rc = send_intcheck_msg(SCRIPT, HOST, MSG);
    assert_int_equal(rc, 0);
}

void test_save_agentless_entry_ok(void **state) {
    (void) state;

    expect_string(__wrap_fopen, path, AGENTLESS_ENTRYDIR "/(" SCRIPT ") " HOST);
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 1);

    expect_any(__wrap_fprintf, __stream);
    expect_string(__wrap_fprintf, formatted_msg, "type: " AGTTYPE "\n");
    will_return(__wrap_fprintf, 0);

    expect_any(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);

    int rc = save_agentless_entry(HOST, SCRIPT, AGTTYPE);
    assert_int_equal(rc, 0);
}

void test_Agentlessd_ok(void **state) {
    (void) state;

    os_calloc(2, sizeof(agentlessd_entries *), lessdc.entries);
    os_calloc(1, sizeof(agentlessd_entries), lessdc.entries[0]);
    lessdc.entries[1] = NULL;

    lessdc.entries[0]->command = NULL;
    lessdc.entries[0]->options = "";
    lessdc.entries[0]->type = NULL;
    lessdc.entries[0]->port = 0;
    lessdc.entries[0]->error_flag = 0;
    
    // enable call to run_periodic_cmd(), minimally...
    // TODO: increase test on run_periodic_cmd() call
    char* pserver = NULL;
    lessdc.entries[0]->server = &pserver;
    lessdc.entries[0]->current_state = 0;
    lessdc.entries[0]->frequency = 86400;
    lessdc.entries[0]->state = LESSD_STATE_PERIODIC;

    expect_StartMQ_call(DEFAULTQUEUE, WRITE, 0);

    will_return(__wrap_FOREVER, 1);
    expect_value(__wrap_sleep, seconds, 2);
    expect_value(__wrap_sleep, seconds, 1);
    expect_value(__wrap_sleep, seconds, 60);
    will_return(__wrap_FOREVER, 0);

    Agentlessd();

    os_free(lessdc.entries[0]);
    os_free(lessdc.entries);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_gen_diff_alert, NULL, NULL),
        cmocka_unit_test_setup_teardown(test_send_log_msg_ok, NULL, NULL),
        cmocka_unit_test_setup_teardown(test_send_log_msg_wrong_sm, NULL, NULL),
        cmocka_unit_test_setup_teardown(test_send_log_msg_fatal_exit, NULL, NULL),
        cmocka_unit_test_setup_teardown(test_send_intcheck_msg_ok, NULL, NULL),
        cmocka_unit_test_setup_teardown(test_save_agentless_entry_ok, NULL, NULL),
        cmocka_unit_test_setup_teardown(test_Agentlessd_ok, NULL, NULL)
    };

    return cmocka_run_group_tests(tests, test_setup, test_teardown);
}

/* Copyright (c) 2015 Nordic Semiconductor. All Rights Reserved.
 *
 * The information contained herein is property of Nordic Semiconductor ASA.
 * Terms and conditions of usage are described in detail in NORDIC
 * SEMICONDUCTOR STANDARD SOFTWARE LICENSE AGREEMENT.
 *
 * Licensees are granted free, non-transferable use of the information. NO
 * WARRANTY of ANY KIND is provided. This heading must NOT be removed from
 * the file.
 *
 */

/** @file

  @brief id manager cunit tests.
*/
#include <string.h>
#include "unity.h"
#include "cmock_peer_database.h"
#include "cmock_peer_data_storage.h"
#include "cmock_ble_gap.h"
#include "cmock_ble_gatts.h"
#include "cmock_ble_conn_state.h"
#include "cmock_nrf_soc.h"
#include "cmock_ble.h"
#include <modules/peer_manager_types.h>
#include <modules/id_manager.h>
#include <zephyr/sys/util.h>


#define MAX_EVT_HANDLER_CALLS       (20)
#define HALF_BLE_GAP_ADDR_LEN       (BLE_GAP_ADDR_LEN / 2)

extern im_connection_t m_connections[IM_MAX_CONN_HANDLES];
extern pm_evt_handler_internal_t const m_evt_handlers[];
extern size_t const im_event_handlers_cnt;
extern uint8_t m_wlisted_peer_cnt;
extern pm_peer_id_t m_wlisted_peers[];

static uint32_t m_test_event_cnt;

static uint16_t      m_conn_handle                = 9;
static pm_peer_id_t  m_peer_id                    = 20;
static uint8_t       m_ediv                       = 40;
static uint8_t       m_rand[BLE_GAP_SEC_RAND_LEN] = {1,2,3,4,5,6,7,8};
static uint8_t       m_addr[BLE_GAP_ADDR_LEN]     = {1,2,3,4,5,6};
static uint8_t       m_irk[BLE_GAP_SEC_KEY_LEN]   = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};

static im_connection_t m_connections_test[IM_MAX_CONN_HANDLES] =
{
    {
        .peer_id      = 5,
        .peer_address = {.addr = {4}}
    },
    {
        .peer_id      = 4,
        .peer_address = {.addr = {3}}
    },
    {
        .peer_id      = 3,
        .peer_address = {.addr = {2}}
    },
    {
        .peer_id      = 2,
        .peer_address = {.addr = {1}}
    },
    {
        .peer_id      = 1,
        .peer_address = {.addr = {0}}
    },
};

static ble_gap_irk_t  m_arbitrary_irk =
{
    .irk = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
};

static pm_evt_t           m_evt_handler_records[MAX_EVT_HANDLER_CALLS];
static nrf_ecb_hal_data_t expected_ecb_hal_data;
static uint8_t            n_ecb_calls = 0xFF;

static pm_peer_data_bonding_t return_im_evt_handler_bonding_data;
static pm_peer_data_bonding_t return_im_peer_id_get_by_master_id_bonding_data;
static pm_peer_data_bonding_t m_bond_data;
static uint32_t               n_im_peer_id_get_by_master_id_callback_calls = 0;
static uint32_t               m_pds_peer_data_iterate_calls_cnt;


void evt_handler_call_record_clear(void)
{
    m_test_event_cnt = 0;
}


void gcm_im_evt_handler(pm_evt_t * p_event)
{
    m_evt_handler_records[m_test_event_cnt++] = *p_event;
}


void pm_im_evt_handler(pm_evt_t * p_event)
{
    m_evt_handler_records[m_test_event_cnt++] = *p_event;
}


void tearDown(void)
{

}


void setUp(void)
{
    evt_handler_call_record_clear();

    m_conn_handle++;
    m_conn_handle = m_conn_handle % 5;
    m_peer_id = m_peer_id % 5;
    m_peer_id++;
    memcpy(m_connections, m_connections_test, sizeof(m_connections));

    // Suppress "Symbol not accessed" lint warnings.
    (void) m_evt_handlers;
}


bool pds_peer_data_iterate_stub_im_evt_handler(pm_peer_data_id_t      data_id,
                                               pm_peer_id_t         * p_peer_id,
                                               pm_peer_data_flash_t * p_peer_data,
                                               int                    cmock_num_calls)
{
    return_im_evt_handler_bonding_data.peer_ble_id.id_addr_info.addr_type = BLE_GAP_ADDR_TYPE_PUBLIC;

    memcpy(return_im_evt_handler_bonding_data.peer_ble_id.id_addr_info.addr, m_addr, BLE_GAP_ADDR_LEN);
    memcpy(return_im_evt_handler_bonding_data.peer_ble_id.id_info.irk,       m_irk,  BLE_GAP_SEC_KEY_LEN);

    *p_peer_id = m_peer_id;
    p_peer_data->p_bonding_data = (pm_peer_data_bonding_t const *) &return_im_evt_handler_bonding_data;

    return true;
}


void test_im_ble_evt_handler(void)
{
    ble_evt_t         ble_evt;
    pm_peer_id_t      invalid_peer_id = PM_PEER_ID_INVALID;

    ble_evt.header.evt_id                     = BLE_GAP_EVT_CONNECTED;
    ble_evt.header.evt_len                    = 19;
    ble_evt.evt.gap_evt.conn_handle           = m_conn_handle;
    ble_evt.evt.gap_evt.params.connected.role = BLE_GAP_ROLE_PERIPH;

    ble_evt.evt.gap_evt.params.connected.peer_addr.addr_type            = BLE_GAP_ADDR_TYPE_PUBLIC;
    ble_evt.evt.gap_evt.params.connected.conn_params.min_conn_interval  = 6;
    ble_evt.evt.gap_evt.params.connected.conn_params.max_conn_interval  = 3200;
    ble_evt.evt.gap_evt.params.connected.conn_params.slave_latency      = 0;
    ble_evt.evt.gap_evt.params.connected.conn_params.conn_sup_timeout   = 10;

    memcpy(ble_evt.evt.gap_evt.params.connected.peer_addr.addr, m_rand, BLE_GAP_ADDR_LEN);

    // Not previously bonded.
    __cmock_pds_peer_data_iterate_prepare_Expect();
    __cmock_pds_peer_data_iterate_ExpectAndReturn(PM_PEER_DATA_ID_BONDING, NULL, NULL, false);
    __cmock_pds_peer_data_iterate_IgnoreArg_p_peer_id();
    __cmock_pds_peer_data_iterate_ReturnThruPtr_p_peer_id(&invalid_peer_id);
    __cmock_pds_peer_data_iterate_IgnoreArg_p_data();

    im_ble_evt_handler(&ble_evt);
    TEST_ASSERT_EQUAL(PM_PEER_ID_INVALID, m_connections[m_conn_handle].peer_id);
    TEST_ASSERT_EQUAL_MEMORY(&ble_evt.evt.gap_evt.params.connected.peer_addr, &m_connections[m_conn_handle].peer_address, sizeof(ble_gap_addr_t));
    TEST_ASSERT_EQUAL_UINT(0 * im_event_handlers_cnt, m_test_event_cnt);

    m_conn_handle++;
    ble_evt.evt.gap_evt.conn_handle++;

    // Previously bonded.
    __cmock_pds_peer_data_iterate_prepare_Expect();
    __cmock_pds_peer_data_iterate_StubWithCallback(pds_peer_data_iterate_stub_im_evt_handler);
    __cmock_pds_peer_data_iterate_ExpectAnyArgsAndReturn(true);

    im_ble_evt_handler(&ble_evt);
    TEST_ASSERT_EQUAL(m_peer_id, m_connections[m_conn_handle].peer_id);
    TEST_ASSERT_EQUAL_MEMORY(&ble_evt.evt.gap_evt.params.connected.peer_addr, &m_connections[m_conn_handle].peer_address, sizeof(ble_gap_addr_t));
    TEST_ASSERT_EQUAL_UINT(1 * im_event_handlers_cnt, m_test_event_cnt);
    TEST_ASSERT_EQUAL_UINT(m_evt_handler_records[0 * im_event_handlers_cnt].conn_handle, m_conn_handle);
    TEST_ASSERT_EQUAL_UINT(m_evt_handler_records[0 * im_event_handlers_cnt].peer_id, m_peer_id);
    TEST_ASSERT_EQUAL_UINT(m_evt_handler_records[0 * im_event_handlers_cnt].evt_id, PM_EVT_BONDED_PEER_CONNECTED);
    evt_handler_call_record_clear();
}


bool addr_compare(ble_gap_addr_t const *p_addr1, ble_gap_addr_t const *p_addr2);

void test_addr_compare(void)
{
    ble_gap_addr_t addr1;
    ble_gap_addr_t addr1_copy;
    ble_gap_addr_t addr2;
    ble_gap_addr_t addr3;

    addr1.addr_type      = BLE_GAP_ADDR_TYPE_RANDOM_STATIC;
    addr1_copy.addr_type = BLE_GAP_ADDR_TYPE_RANDOM_STATIC;
    addr2.addr_type      = BLE_GAP_ADDR_TYPE_RANDOM_STATIC;
    addr3.addr_type      = BLE_GAP_ADDR_TYPE_RANDOM_PRIVATE_NON_RESOLVABLE;

    for (int i = 0; i < BLE_GAP_ADDR_LEN; i++)
    {
        addr1.addr[i]      = 0xFF;
        addr1_copy.addr[i] = 0xFF;
        addr2.addr[i]      = 0xFE;
        addr3.addr[i]      = 0xFF;
    }

    TEST_ASSERT_EQUAL_UINT8(true, addr_compare(&addr1, &addr1_copy));
    TEST_ASSERT_EQUAL_UINT8(false, addr_compare(&addr1, &addr2));
    TEST_ASSERT_EQUAL_UINT8(false, addr_compare(&addr1, &addr3));
}


void find_duplicate_prepare(pm_peer_data_t * p_peer_data, bool expect_find)
{
    __cmock_pds_peer_data_iterate_prepare_Expect();
    __cmock_pds_peer_data_iterate_ExpectAndReturn(PM_PEER_DATA_ID_BONDING, NULL, NULL, true);
    __cmock_pds_peer_data_iterate_IgnoreArg_p_peer_id();
    __cmock_pds_peer_data_iterate_IgnoreArg_p_data();
    __cmock_pds_peer_data_iterate_ReturnThruPtr_p_peer_id(&m_peer_id);
    __cmock_pds_peer_data_iterate_ReturnThruPtr_p_data((pm_peer_data_flash_t*)(p_peer_data));
    if (!expect_find)
    {
        __cmock_pds_peer_data_iterate_ExpectAndReturn(PM_PEER_DATA_ID_BONDING, NULL, NULL, false);
        __cmock_pds_peer_data_iterate_IgnoreArg_p_peer_id();
        __cmock_pds_peer_data_iterate_IgnoreArg_p_data();
    }
}


void duplicate_bonding_data_test(ble_gap_irk_t * p_irk1, ble_gap_addr_t * p_addr1, ble_gap_irk_t * p_irk2, ble_gap_addr_t * p_addr2, bool expected_ret)
{
    // Test both im_is_duplicate_bonding_data() and im_find_duplicate_bonding_data().
    pm_peer_data_bonding_t bonding_data1 = {0};
    pm_peer_data_bonding_t bonding_data2 = {0};
    pm_peer_data_t peer_data1 = {.length_words = PM_BONDING_DATA_N_WORDS(),
                                 .data_id = PM_PEER_DATA_ID_BONDING};

    bonding_data1.peer_ble_id.id_info      = *p_irk1;
    bonding_data1.peer_ble_id.id_addr_info = *p_addr1;
    bonding_data2.peer_ble_id.id_info      = *p_irk2;
    bonding_data2.peer_ble_id.id_addr_info = *p_addr2;
    peer_data1.p_bonding_data              = &bonding_data1;

    bool ret = im_is_duplicate_bonding_data(&bonding_data1, &bonding_data2);

    TEST_ASSERT_EQUAL(expected_ret, ret);

    find_duplicate_prepare(&peer_data1, expected_ret);
    pm_peer_id_t peer_id = im_find_duplicate_bonding_data(&bonding_data2, PM_PEER_ID_INVALID);
    TEST_ASSERT_EQUAL(expected_ret ? m_peer_id : PM_PEER_ID_INVALID, peer_id);

    // Skip peer ID
    find_duplicate_prepare(&peer_data1, false);
    peer_id = im_find_duplicate_bonding_data(&bonding_data2, m_peer_id);
    TEST_ASSERT_EQUAL(PM_PEER_ID_INVALID, peer_id);
}


void test_duplicate_bonding_data(void)
{
    ble_gap_irk_t valid_irk1  = {.irk = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,100}};
    ble_gap_irk_t valid_irk2  = {.irk = {20,0,0,0,0,0,0,0,0,0,0,0,0,0,0,100}};
    ble_gap_irk_t invalid_irk = {.irk = {0}};

    ble_gap_addr_t addr_rpr  = {.addr = {1,1,1,1,1,1}, .addr_type = BLE_GAP_ADDR_TYPE_RANDOM_PRIVATE_RESOLVABLE};
    ble_gap_addr_t addr_rpnr = {.addr = {1,1,1,1,1,2}, .addr_type = BLE_GAP_ADDR_TYPE_RANDOM_PRIVATE_NON_RESOLVABLE};
    ble_gap_addr_t addr_rs   = {.addr = {1,1,1,1,1,3}, .addr_type = BLE_GAP_ADDR_TYPE_RANDOM_STATIC};
    ble_gap_addr_t addr_p    = {.addr = {1,1,1,1,1,4}, .addr_type = BLE_GAP_ADDR_TYPE_PUBLIC};

    duplicate_bonding_data_test(&valid_irk1,  &addr_rs,   &valid_irk1,  &addr_rs,   true);  // Same id addr, same IRK.
    duplicate_bonding_data_test(&valid_irk1,  &addr_rs,   &valid_irk2,  &addr_rs,   true);  // Same id addr, different IRK.
    duplicate_bonding_data_test(&invalid_irk, &addr_rs,   &invalid_irk, &addr_rs,   true);  // Same id addr, same invalid IRK.
    duplicate_bonding_data_test(&valid_irk1,  &addr_rpr,  &valid_irk1,  &addr_rpr,  true);  // Same non-id addr, same IRK.
    duplicate_bonding_data_test(&valid_irk1,  &addr_rpnr, &valid_irk2,  &addr_rpnr, false); // Same non-id addr, different IRK.
    duplicate_bonding_data_test(&valid_irk2,  &addr_p,    &valid_irk2,  &addr_rs,   false); // different id addr, same IRK.
    duplicate_bonding_data_test(&valid_irk2,  &addr_rpnr, &valid_irk2,  &addr_rpr,  true);  // different non-id addr, same IRK.
    duplicate_bonding_data_test(&invalid_irk, &addr_rpnr, &invalid_irk, &addr_rpr,  false); // different non-id addr, same invalid IRK.
    duplicate_bonding_data_test(&invalid_irk, &addr_rpnr, &valid_irk2,  &addr_rpr,  false); // different non-id addr, one invalid IRK.
    duplicate_bonding_data_test(&valid_irk1,  &addr_rpnr, &invalid_irk, &addr_rpr,  false); // different non-id addr, one invalid IRK.
    duplicate_bonding_data_test(&valid_irk1,  &addr_rpnr, &valid_irk2,  &addr_rpr,  false); // different non-id addr, different IRK.
    duplicate_bonding_data_test(&valid_irk1,  &addr_rpnr, &valid_irk1,  &addr_rs,   true);  // id addr + non-id addr, same IRK.
    duplicate_bonding_data_test(&valid_irk1,  &addr_p,    &valid_irk1,  &addr_rpr,  true);  // id addr + non-id addr, same IRK.
}


void test_master_id_compare(void)
{
    ble_gap_master_id_t master_id1;
    ble_gap_master_id_t master_id2;
    ble_gap_master_id_t master_id3;
    ble_gap_master_id_t master_id4;
    // Initialize master_id3 with a ediv different from master_id1
    master_id1.ediv = m_ediv;
    master_id2.ediv = m_ediv;
    master_id3.ediv = m_ediv + 1;
    master_id4.ediv = m_ediv;
    // Initialize master_id3 with a rand different from master_id1
    for (int i = 0; i < BLE_GAP_SEC_RAND_LEN; i++)
    {
        master_id1.rand[i] = m_rand[i];
        master_id2.rand[i] = m_rand[i];
        master_id3.rand[i] = m_rand[i];
        master_id4.rand[i] = m_rand[i] + 1;
    }
    TEST_ASSERT_EQUAL_UINT(true, im_master_ids_compare((ble_gap_master_id_t const *) &master_id1, (ble_gap_master_id_t const *) &master_id2));
    TEST_ASSERT_EQUAL_UINT(false, im_master_ids_compare((ble_gap_master_id_t const *) &master_id1, (ble_gap_master_id_t const *) &master_id3));
    TEST_ASSERT_EQUAL_UINT(false, im_master_ids_compare((ble_gap_master_id_t const *) &master_id1, (ble_gap_master_id_t const *) &master_id4));

    // Test comparison of invalid master IDs.
    ble_gap_master_id_t empty_master_id1;
    ble_gap_master_id_t empty_master_id2;
    empty_master_id1.ediv = 0;
    empty_master_id2.ediv = 0;
    for (int i = 0; i < BLE_GAP_SEC_RAND_LEN; i++)
    {
        empty_master_id1.rand[i] = 0;
        empty_master_id2.rand[i] = 0;
    }
    TEST_ASSERT_EQUAL_UINT(false, im_master_ids_compare((ble_gap_master_id_t const *) &empty_master_id1, (ble_gap_master_id_t const *) &empty_master_id2));
}


bool pds_peer_data_iterate_stub_im_peer_id_get_by_master_id(pm_peer_data_id_t data_id, pm_peer_id_t * p_peer_id, pm_peer_data_flash_t * p_peer_data, int cmock_num_calls)
{
    if (n_im_peer_id_get_by_master_id_callback_calls < 1)
    {
        return_im_peer_id_get_by_master_id_bonding_data.own_ltk.master_id.ediv = m_ediv + 1;
        memcpy(return_im_peer_id_get_by_master_id_bonding_data.own_ltk.master_id.rand, m_rand, BLE_GAP_SEC_RAND_LEN);
    } else {
        return_im_peer_id_get_by_master_id_bonding_data.own_ltk.master_id.ediv = m_ediv;
        memcpy(return_im_peer_id_get_by_master_id_bonding_data.own_ltk.master_id.rand, m_rand, BLE_GAP_SEC_RAND_LEN);
    }
    p_peer_data->p_bonding_data = (pm_peer_data_bonding_t const *) &return_im_peer_id_get_by_master_id_bonding_data;
    n_im_peer_id_get_by_master_id_callback_calls++;

    *p_peer_id = m_peer_id;
    return true;
}


void test_im_peer_id_get_by_master_id(void)
{
    pm_peer_id_t        peer_id;
    ble_gap_master_id_t master_id;

    // Test correct behavior with a matching master id
    __cmock_pds_peer_data_iterate_prepare_Expect();
    __cmock_pds_peer_data_iterate_StubWithCallback(pds_peer_data_iterate_stub_im_peer_id_get_by_master_id);
    __cmock_pds_peer_data_iterate_ExpectAnyArgsAndReturn(true);
    __cmock_pds_peer_data_iterate_ExpectAnyArgsAndReturn(true);


    master_id.ediv = m_ediv;
    memcpy(master_id.rand, m_rand, BLE_GAP_SEC_RAND_LEN);

    peer_id = im_peer_id_get_by_master_id(&master_id);
    TEST_ASSERT_EQUAL_UINT(m_peer_id, peer_id);

    // Test correct behavior with no peer with matching master id
}


void test_im_master_id_is_valid(void)
{
    ble_gap_master_id_t valid_master_id;
    ble_gap_master_id_t invalid_master_id;

    valid_master_id.ediv = 1;
    invalid_master_id.ediv = 0;
    for (int i = 0; i < BLE_GAP_SEC_RAND_LEN; i++)
    {
        valid_master_id.rand[i] = i;
        invalid_master_id.rand[i] = 0;
    }
    TEST_ASSERT_EQUAL_UINT(true, im_master_id_is_valid((ble_gap_master_id_t const *) &valid_master_id));
    TEST_ASSERT_EQUAL_UINT(false, im_master_id_is_valid((ble_gap_master_id_t const *) &invalid_master_id));
}


// Running this test will cause the id manager to populate the first two elements in m_im.connections as shown here:
// [{m_conn_handle, m_peer_id}, {m_conn_handle + 1, m_peer_id + 1}, ...]
void test_im_new_peer_id(void)
{
    im_new_peer_id(m_conn_handle, m_peer_id);
    TEST_ASSERT_EQUAL_UINT(m_peer_id, m_connections[m_conn_handle].peer_id);

    // Don't mangle memory. Should be caught as segfault if it happens.
    im_new_peer_id(BLE_CONN_HANDLE_INVALID-1, m_peer_id);
}


void test_im_peer_free(void)
{
    __cmock_ble_conn_state_valid_ExpectAndReturn(0, true);
    __cmock_ble_conn_state_valid_IgnoreArg_conn_handle();
    uint16_t conn_handle = im_conn_handle_get(m_peer_id);

    // Error from pdb_peer_free, don't disassociate.
    __cmock_ble_conn_state_valid_ExpectAndReturn(conn_handle, true);
    __cmock_pdb_peer_free_ExpectAndReturn(m_peer_id, NRF_ERROR_INTERNAL);
    TEST_ASSERT_EQUAL(NRF_ERROR_INTERNAL, im_peer_free(m_peer_id));
    TEST_ASSERT_NOT_EQUAL(PM_PEER_ID_INVALID, m_connections[conn_handle].peer_id);

    // invalid conn handle, don't disassociate.
    __cmock_ble_conn_state_valid_ExpectAndReturn(conn_handle, false);
    __cmock_pdb_peer_free_ExpectAndReturn(m_peer_id, NRF_SUCCESS);
    TEST_ASSERT_EQUAL(NRF_SUCCESS, im_peer_free(m_peer_id));
    TEST_ASSERT_NOT_EQUAL(PM_PEER_ID_INVALID, m_connections[conn_handle].peer_id);

    // pdb_peer_free successful, disassociate.
    __cmock_ble_conn_state_valid_ExpectAndReturn(conn_handle, true);
    __cmock_pdb_peer_free_ExpectAndReturn(m_peer_id, NRF_SUCCESS);
    TEST_ASSERT_EQUAL(NRF_SUCCESS, im_peer_free(m_peer_id));
    TEST_ASSERT_EQUAL(PM_PEER_ID_INVALID, m_connections[conn_handle].peer_id);

    // pdb_peer_free successful, not connected. Should segfault if memory is accessed.
    m_peer_id += 20;
    __cmock_pdb_peer_free_ExpectAndReturn(m_peer_id, NRF_SUCCESS);
    TEST_ASSERT_EQUAL(NRF_SUCCESS, im_peer_free(m_peer_id));
}


void test_im_peer_id_get_by_conn_handle(void)
{
    // Get the peer id of the peer with m_conn_handle.
    __cmock_ble_conn_state_valid_ExpectAndReturn(m_conn_handle, true);
    TEST_ASSERT_EQUAL_UINT(m_connections_test[m_conn_handle].peer_id, im_peer_id_get_by_conn_handle(m_conn_handle));

    // Get the peer id of invalid conn handle.
    __cmock_ble_conn_state_valid_ExpectAndReturn(m_conn_handle, false);
    TEST_ASSERT_EQUAL_UINT(PM_PEER_ID_INVALID, im_peer_id_get_by_conn_handle(m_conn_handle));
    TEST_ASSERT_EQUAL_UINT(PM_PEER_ID_INVALID, im_peer_id_get_by_conn_handle(m_conn_handle + IM_MAX_CONN_HANDLES));
    TEST_ASSERT_EQUAL_UINT(PM_PEER_ID_INVALID, im_peer_id_get_by_conn_handle(BLE_CONN_HANDLE_INVALID));
}


void test_im_conn_handle_get(void)
{
    uint16_t conn_handle;

    // Get the conn handle of the peer with m_peer_id.
    __cmock_ble_conn_state_valid_ExpectAndReturn(0, true);
    __cmock_ble_conn_state_valid_IgnoreArg_conn_handle();
    conn_handle = im_conn_handle_get(m_peer_id);
    TEST_ASSERT(conn_handle < IM_MAX_CONN_HANDLES);
    TEST_ASSERT_EQUAL_UINT(m_peer_id, m_connections[conn_handle].peer_id); //lint !e661

    // Attempt to get a conn handle for an invalid peer id.
    __cmock_ble_conn_state_valid_ExpectAndReturn(conn_handle, false);
    TEST_ASSERT_EQUAL_UINT(BLE_CONN_HANDLE_INVALID, im_conn_handle_get(m_peer_id));
    TEST_ASSERT_EQUAL_UINT(BLE_CONN_HANDLE_INVALID, im_conn_handle_get(m_peer_id + 20));
    TEST_ASSERT_EQUAL_UINT(BLE_CONN_HANDLE_INVALID, im_conn_handle_get(PM_PEER_ID_INVALID));
}

void test_im_ble_addr_get(void)
{
    ble_gap_addr_t addr;

    // Conn handle too large
    TEST_ASSERT_EQUAL(BLE_ERROR_INVALID_CONN_HANDLE, im_ble_addr_get(IM_MAX_CONN_HANDLES, &addr));

    // Conn handle invalid
    __cmock_ble_conn_state_valid_ExpectAndReturn(m_conn_handle, false);
    TEST_ASSERT_EQUAL(BLE_ERROR_INVALID_CONN_HANDLE, im_ble_addr_get(m_conn_handle, &addr));

    // Success
    __cmock_ble_conn_state_valid_ExpectAndReturn(m_conn_handle, true);
    TEST_ASSERT_EQUAL(NRF_SUCCESS, im_ble_addr_get(m_conn_handle, &addr));
    TEST_ASSERT_EQUAL_MEMORY(&m_connections_test[m_conn_handle].peer_address, &addr, sizeof(addr));
}


bool pds_peer_data_iterate_stub_im_whitelist_create(pm_peer_data_id_t      data_id,
                                                    pm_peer_id_t         * p_peer_id,
                                                    pm_peer_data_flash_t * p_peer_data,
                                                    int                    cmock_num_calls)
{
    memcpy(m_bond_data.peer_ble_id.id_info.irk,       m_irk,  BLE_GAP_SEC_KEY_LEN);
    memcpy(m_bond_data.peer_ble_id.id_addr_info.addr, m_addr, BLE_GAP_ADDR_LEN);

    m_bond_data.peer_ble_id.id_addr_info.addr_type = BLE_GAP_ADDR_TYPE_PUBLIC;
    m_bond_data.peer_ble_id.id_info.irk[0]         = m_irk[0]  + m_pds_peer_data_iterate_calls_cnt;
    m_bond_data.peer_ble_id.id_addr_info.addr[0]   = m_addr[0] + m_pds_peer_data_iterate_calls_cnt;

    *p_peer_id                  = m_pds_peer_data_iterate_calls_cnt++;
    p_peer_data->p_bonding_data = &m_bond_data;

    return m_pds_peer_data_iterate_calls_cnt < 9 ? true : false;
}


void test_im_id_addr_set(void)
{
    uint32_t ret;
    ble_gap_addr_t public_addr = {.addr = {1,2,3,4,5,6}, .addr_type = BLE_GAP_ADDR_TYPE_PUBLIC};

    __cmock_sd_ble_gap_addr_set_ExpectAndReturn(&public_addr, NRF_SUCCESS);
    ret = im_id_addr_set(&public_addr);
    TEST_ASSERT_EQUAL(NRF_SUCCESS, ret);
}


void test_im_id_addr_get(void)
{
    uint32_t ret;
    ble_gap_addr_t out_addr = {0};

    __cmock_sd_ble_gap_addr_get_ExpectWithArrayAndReturn(&out_addr, 1, NRF_SUCCESS);
    ret = im_id_addr_get(&out_addr);
    TEST_ASSERT_EQUAL(NRF_SUCCESS, ret);
}

void test_im_privacy_set(void)
{
    uint32_t ret;

    pm_privacy_params_t privacy_params_on  =
    {
        .privacy_mode         = BLE_GAP_PRIVACY_MODE_DEVICE_PRIVACY,
        .private_addr_type    = BLE_GAP_ADDR_TYPE_RANDOM_PRIVATE_RESOLVABLE,
        .private_addr_cycle_s = 24, // arbitrary
        .p_device_irk         = &m_arbitrary_irk,
    };

    __cmock_sd_ble_gap_privacy_set_ExpectWithArrayAndReturn((ble_gap_privacy_params_t*)&privacy_params_on, 1, NRF_SUCCESS);
    ret = im_privacy_set((pm_privacy_params_t*)&privacy_params_on);

    TEST_ASSERT_EQUAL(ret, NRF_SUCCESS);
}


void test_im_privacy_get(void)
{
    uint32_t ret;
    ble_gap_irk_t       irk_out;
    pm_privacy_params_t privacy_params_out = {.p_device_irk = &irk_out};

    __cmock_sd_ble_gap_privacy_get_ExpectWithArrayAndReturn(&privacy_params_out, 1, NRF_SUCCESS);

    ret = im_privacy_get(&privacy_params_out);
    TEST_ASSERT_EQUAL(NRF_SUCCESS, ret);
}

uint32_t pds_peer_data_read_stub(pm_peer_id_t              peer_id,
                                   pm_peer_data_id_t         data_id,
                                   pm_peer_data_t          * p_data,
                                   uint32_t          const * buf_size,
                                   int                       cmock_num_calls)
{
    ble_gap_addr_t addr_public =
    {
        .addr_id_peer = 0,
        .addr_type    = BLE_GAP_ADDR_TYPE_PUBLIC,
        .addr         = {42, 1, 2, 3, 4, 5}
    };

    switch (cmock_num_calls)
    {
        case 0:
            return NRF_ERROR_NOT_FOUND;

        case 1:
            return NRF_ERROR_INVALID_PARAM;

        case 2:
            // This address type is no good for whitelist.
            p_data->p_bonding_data->peer_ble_id.id_addr_info.addr_type = BLE_GAP_ADDR_TYPE_RANDOM_PRIVATE_RESOLVABLE;
            return NRF_SUCCESS;

        case 3:
        case 4:
        case 5:
            memcpy(&p_data->p_bonding_data->peer_ble_id.id_addr_info, &addr_public, sizeof(ble_gap_addr_t));
            p_data->p_bonding_data->peer_ble_id.id_addr_info.addr[0] = cmock_num_calls;
            return NRF_SUCCESS;


        default:
            TEST_ASSERT_TRUE_MESSAGE(false, "There could be a problem here.");
            return NRF_ERROR_INTERNAL;
    }
}

uint32_t pds_peer_data_read_stub_whitelist_get(pm_peer_id_t              peer_id,
                                                 pm_peer_data_id_t         data_id,
                                                 pm_peer_data_t          * p_data,
                                                 uint32_t          const * buf_size,
                                                 int                       cmock_num_calls)
{
    ble_gap_addr_t dummy_addr;

    memset(&dummy_addr, 0x00, sizeof(dummy_addr));

    memcpy(dummy_addr.addr, m_addr, BLE_GAP_ADDR_LEN);
    memcpy(&p_data->p_bonding_data->peer_ble_id.id_addr_info, &dummy_addr, sizeof(ble_gap_addr_t));

    p_data->p_bonding_data->peer_ble_id.id_addr_info.addr[0] = cmock_num_calls;

    return NRF_SUCCESS;
}


void test_im_whitelist_get(void)
{
    uint32_t ret;
    pm_peer_id_t peers[] = {1, 2, 3};
    uint32_t     wlisted_peer_cnt = BLE_GAP_WHITELIST_ADDR_MAX_COUNT;

    ble_gap_addr_t dummy_addr;
    ble_gap_addr_t addrs[BLE_GAP_WHITELIST_ADDR_MAX_COUNT];
    ble_gap_irk_t  irks[BLE_GAP_WHITELIST_ADDR_MAX_COUNT];

    memset(&dummy_addr, 0x00, sizeof(dummy_addr));
    memset(addrs,       0x00, sizeof(addrs));
    memset(irks,        0x00, sizeof(irks));

    memcpy(dummy_addr.addr, m_addr, BLE_GAP_ADDR_LEN);

    // Whitelist three peers first.

    memcpy(m_wlisted_peers, peers, sizeof(peers));
    m_wlisted_peer_cnt = 3;

    // When im_whitelist_get() is called, the Peer Manager will attempt
    // to fetch addresses and IRKs of the peers previously whitelisted.

    // This stup loads three peers from flash, with address
    // {0, 2, 3, 4, 5, 6}
    // {1, 2, 3, 4, 5, 6}
    // {2, 2, 3, 4, 5, 6}

    __cmock_pds_peer_data_read_StubWithCallback(pds_peer_data_read_stub_whitelist_get);
    __cmock_pds_peer_data_read_ExpectAnyArgsAndReturn(NRF_SUCCESS);
    __cmock_pds_peer_data_read_ExpectAnyArgsAndReturn(NRF_SUCCESS);
    __cmock_pds_peer_data_read_ExpectAnyArgsAndReturn(NRF_SUCCESS);

    ret = im_whitelist_get((ble_gap_addr_t*)addrs, &wlisted_peer_cnt,
                           NULL, NULL); // Don't fetch IRKs

    TEST_ASSERT_EQUAL(NRF_SUCCESS, ret);
    TEST_ASSERT_EQUAL(3,           wlisted_peer_cnt);

    for (uint32_t i = 0; i < 3; i++)
    {
        dummy_addr.addr[0] = i;
        TEST_ASSERT_EQUAL_MEMORY(&addrs[i], &dummy_addr, sizeof(ble_gap_addr_t));
    }
}


void test_im_whitelist_set_clear(void)
{
    uint32_t ret;
    pm_peer_id_t peers[] = {0, 1, 2, 3, 4, 5};

    __cmock_sd_ble_gap_whitelist_set_ExpectAndReturn(NULL, 0, NRF_SUCCESS);
    ret = im_whitelist_set(NULL, 0);

    TEST_ASSERT_EQUAL(NRF_SUCCESS, ret);

    __cmock_sd_ble_gap_whitelist_set_ExpectAndReturn(NULL, 0, NRF_SUCCESS);
    ret = im_whitelist_set(peers, 0);

    TEST_ASSERT_EQUAL(NRF_SUCCESS, ret);

    __cmock_sd_ble_gap_whitelist_set_ExpectAndReturn(NULL, 0, NRF_SUCCESS);
    ret = im_whitelist_set(NULL, 0x123);

    TEST_ASSERT_EQUAL(NRF_SUCCESS, ret);
}


void test_im_whitelist_set(void)
{
    uint32_t ret;
    pm_peer_id_t       peers[]  = {1, 2, 3};
    uint32_t     const peer_cnt = (sizeof(peers) / sizeof(pm_peer_id_t));

    __cmock_pds_peer_data_read_StubWithCallback(pds_peer_data_read_stub);
    __cmock_pds_peer_data_read_ExpectAnyArgsAndReturn(NRF_SUCCESS);

    // Peer is not valid.
    ret = im_whitelist_set(peers, peer_cnt);
    TEST_ASSERT_EQUAL(NRF_ERROR_NOT_FOUND, ret);

    __cmock_pds_peer_data_read_ExpectAnyArgsAndReturn(NRF_SUCCESS);

    // Peer is valid, but there is no data in flash.
    ret = im_whitelist_set(peers, peer_cnt);
    TEST_ASSERT_EQUAL(NRF_ERROR_NOT_FOUND, ret);

    __cmock_pds_peer_data_read_ExpectAnyArgsAndReturn(NRF_SUCCESS);

    // Peer data was found but the peer address can not be whitelisted.
    ret = im_whitelist_set(peers, peer_cnt);
    TEST_ASSERT_EQUAL(BLE_ERROR_GAP_INVALID_BLE_ADDR, ret);

    __cmock_sd_ble_gap_whitelist_set_ExpectAndReturn(NULL, peer_cnt, NRF_SUCCESS);
    __cmock_sd_ble_gap_whitelist_set_IgnoreArg_pp_wl_addrs();
    __cmock_pds_peer_data_read_ExpectAnyArgsAndReturn(NRF_SUCCESS);
    __cmock_pds_peer_data_read_ExpectAnyArgsAndReturn(NRF_SUCCESS);
    __cmock_pds_peer_data_read_ExpectAnyArgsAndReturn(NRF_SUCCESS);

    ret = im_whitelist_set(peers, peer_cnt);
    TEST_ASSERT_EQUAL(NRF_SUCCESS, ret);


    TEST_ASSERT_EQUAL(peer_cnt, m_wlisted_peer_cnt);
}

static pm_peer_data_bonding_t data[3] = {{.peer_ble_id = {.id_addr_info = {.addr = {1}, .addr_type = BLE_GAP_ADDR_TYPE_RANDOM_STATIC}}},
                                         {.peer_ble_id = {.id_addr_info = {.addr = {2}, .addr_type = BLE_GAP_ADDR_TYPE_RANDOM_STATIC}}},
                                         {.peer_ble_id = {.id_addr_info = {.addr = {3}, .addr_type = BLE_GAP_ADDR_TYPE_RANDOM_STATIC}}}};
uint32_t sd_ble_gap_device_identities_set_stub(ble_gap_id_key_t const * const * pp_id_keys, ble_gap_irk_t const * const * pp_local_irks, uint8_t len, int numCalls)
{
    TEST_ASSERT_EQUAL(0, numCalls);
    TEST_ASSERT_NULL(pp_local_irks);
    TEST_ASSERT_EQUAL(3, len);

    for (int i = 0; i < 3; i++)
    {
        TEST_ASSERT_EQUAL_MEMORY(&data[i].peer_ble_id, pp_id_keys[i], sizeof(pm_peer_data_t));
    }
    return NRF_SUCCESS;
}

void test_im_device_identities_list_set(void)
{
    uint32_t ret;
    pm_peer_id_t peers[3] = {1,2,3};

    ret = im_device_identities_list_set(NULL, BLE_GAP_DEVICE_IDENTITIES_MAX_COUNT + 1);
    TEST_ASSERT_EQUAL(NRF_ERROR_INVALID_PARAM, ret);

    __cmock_sd_ble_gap_device_identities_set_ExpectAndReturn(NULL, NULL, 0, NRF_SUCCESS);
    ret = im_device_identities_list_set(NULL, BLE_GAP_DEVICE_IDENTITIES_MAX_COUNT);
    TEST_ASSERT_EQUAL(NRF_SUCCESS, ret);

    __cmock_pds_peer_data_read_ExpectAndReturn(peers[0], PM_PEER_DATA_ID_BONDING, NULL, NULL, NRF_ERROR_NOT_FOUND);
    __cmock_pds_peer_data_read_IgnoreArg_p_data();
    __cmock_pds_peer_data_read_IgnoreArg_p_buf_len();
    ret = im_device_identities_list_set(peers, 3);
    TEST_ASSERT_EQUAL(NRF_ERROR_NOT_FOUND, ret);

    for (int i = 0; i < 3; i++)
    {
        pm_peer_data_t mdata;
        mdata.p_bonding_data = &data[i];
        __cmock_pds_peer_data_read_ExpectAndReturn(peers[i], PM_PEER_DATA_ID_BONDING, NULL, NULL, NRF_SUCCESS);
        __cmock_pds_peer_data_read_IgnoreArg_p_data();
        __cmock_pds_peer_data_read_IgnoreArg_p_buf_len();
        __cmock_pds_peer_data_read_ReturnThruPtr_p_data(&mdata);
    }
    __cmock_sd_ble_gap_device_identities_set_StubWithCallback(sd_ble_gap_device_identities_set_stub);
    __cmock_sd_ble_gap_device_identities_set_ExpectAnyArgsAndReturn(NRF_SUCCESS);
    ret = im_device_identities_list_set(peers, 3);
    TEST_ASSERT_EQUAL(NRF_SUCCESS, ret);
}


uint32_t callback(nrf_ecb_hal_data_t* p_ecb_data, int cmock_num_calls)
{
    for (uint32_t i = 0; i < SOC_ECB_KEY_LENGTH; i++)
    {
        TEST_ASSERT_EQUAL_UINT_MESSAGE(n_ecb_calls,
                                       cmock_num_calls,
                                       "Unexpected callback received from cmock.");

        TEST_ASSERT_EQUAL_UINT_MESSAGE(expected_ecb_hal_data.key[i],
                                       p_ecb_data->key[i],
                                       "Wrong key sent to ecb.");

        TEST_ASSERT_EQUAL_UINT_MESSAGE(expected_ecb_hal_data.cleartext[i],
                                       p_ecb_data->cleartext[i],
                                       "Wrong address sent to ecb.");
    }

    uint8_t hash_array[SOC_ECB_KEY_LENGTH] =
        {0x15,0x9d,0x5f,0xb7,0x2e,0xbe,0x23,0x11,0xa4,0x8c,0x1b,0xdc,0xc4,0x0d,0xfb,0xaa};

    for (uint32_t i = 0; i < SOC_ECB_KEY_LENGTH; i++)
    {
        p_ecb_data->ciphertext[i] = hash_array[i];
    }

    return NRF_SUCCESS;
}


void test_im_address_resolve(void)
{
    ble_gap_addr_t addr;
    ble_gap_irk_t irk;
    addr.addr_type = BLE_GAP_ADDR_TYPE_RANDOM_PRIVATE_RESOLVABLE;
    uint8_t addr_array[6] = {0xaa,0xfb,0x0d,0x70,0x81,0x94};
    uint8_t irk_array[SOC_ECB_KEY_LENGTH]
        = {0xec,0x02,0x34,0xa3,0x57,0xc8,0xad,0x05,0x34,0x10,0x10,0xa6,0x0a,0x39,0x7d,0x9b};
    for (uint32_t i = 0; i < BLE_GAP_ADDR_LEN; i++)
    {
        addr.addr[i] = addr_array[i];
    }
    for (uint32_t i = 0; i < SOC_ECB_KEY_LENGTH; i++)
    {
        irk.irk[i] = irk_array[i];
        expected_ecb_hal_data.key[i] = irk_array[15 - i];
    }
    memset(expected_ecb_hal_data.cleartext, 0, SOC_ECB_KEY_LENGTH - HALF_BLE_GAP_ADDR_LEN);
    memset(expected_ecb_hal_data.ciphertext, 0, SOC_ECB_KEY_LENGTH - HALF_BLE_GAP_ADDR_LEN);
    for (uint32_t i = 0; i < HALF_BLE_GAP_ADDR_LEN; i++)
    {
        expected_ecb_hal_data.cleartext[SOC_ECB_KEY_LENGTH - 1 - i] =
            addr_array[HALF_BLE_GAP_ADDR_LEN + i];
        expected_ecb_hal_data.ciphertext[SOC_ECB_KEY_LENGTH - 1 - i] = addr_array[i];
    }
    __cmock_sd_ecb_block_encrypt_StubWithCallback(callback);
    __cmock_sd_ecb_block_encrypt_ExpectAnyArgsAndReturn(NRF_SUCCESS);
    n_ecb_calls = 0;
    TEST_ASSERT_EQUAL_UINT(true, im_address_resolve(&addr, &irk));
}

extern int unity_main(void);

int main(void)
{
	(void)unity_main();

	return 0;
}

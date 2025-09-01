/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <unity.h>
#include <stdint.h>
#include <errno.h>

#include "cmock_peer_id.h"
#include "cmock_zms.h"

#include "modules/peer_data_storage.h"

static uint32_t peer_id_peer_data_type_to_entry_id(uint16_t peer_id,
                                                   enum pm_peer_data_type data_type)
{
        return (peer_id * PM_PEER_DATA_TYPE_LAST) + data_type;
}

void setUp(void)
{
}

void tearDown(void)
{
	pds_reset();
}

void test_pds_init_efault(void)
{
	int err;

	__cmock_zms_evt_handler_set_IgnoreAndReturn(-EINVAL);

	err = pds_init();
	TEST_ASSERT_EQUAL(-EFAULT, err);
}

void test_pds_init_enomem(void)
{
	int err;

	__cmock_zms_evt_handler_set_IgnoreAndReturn(0);
	__cmock_zms_mount_IgnoreAndReturn(-EINVAL);

	err = pds_init();
	TEST_ASSERT_EQUAL(-ENOMEM, err);
}

void test_pds_init(void)
{
	int err;

	__cmock_zms_evt_handler_set_IgnoreAndReturn(0);
	__cmock_zms_mount_IgnoreAndReturn(0);
	__cmock_peer_id_init_Ignore();

        for (uint16_t i = 0; i < CONFIG_PM_PEER_ID_N_AVAILABLE_IDS; i++) {
                __cmock_peer_id_alloc_ExpectAndReturn(i, 0);
        }

	err = pds_init();
	TEST_ASSERT_EQUAL(0, err);
}

void test_pds_peer_data_read_eperm(void)
{
	int err;
	uint16_t peer_id = 0;
	enum pm_peer_data_type data_type = PM_PEER_DATA_TYPE_BONDING;

	err = pds_peer_data_read(peer_id, data_type, NULL, NULL);
	TEST_ASSERT_EQUAL(-EPERM, err);
}

void test_pds_peer_data_read_einval(void)
{
	int err;
	uint16_t peer_id = 0;
	uint16_t peer_id_invalid = PM_PEER_ID_INVALID;
	enum pm_peer_data_type data_type = PM_PEER_DATA_TYPE_BONDING;
	enum pm_peer_data_type data_type_invalid = PM_PEER_DATA_TYPE_INVALID;
	struct pm_peer_data peer_data;
	size_t len;

	__cmock_zms_evt_handler_set_IgnoreAndReturn(0);
	__cmock_zms_mount_IgnoreAndReturn(0);
	__cmock_peer_id_init_Ignore();

        for (uint16_t i = 0; i < CONFIG_PM_PEER_ID_N_AVAILABLE_IDS; i++) {
                __cmock_peer_id_alloc_ExpectAndReturn(i, 0);
        }

	err = pds_init();
	TEST_ASSERT_EQUAL(0, err);

	err = pds_peer_data_read(peer_id_invalid, data_type, &peer_data, &len);
	TEST_ASSERT_EQUAL(-EINVAL, err);

	err = pds_peer_data_read(peer_id, data_type_invalid, &peer_data, &len);
	TEST_ASSERT_EQUAL(-EINVAL, err);

	err = pds_peer_data_read(peer_id, data_type, NULL, &len);
	TEST_ASSERT_EQUAL(-EINVAL, err);

	err = pds_peer_data_read(peer_id, data_type, &peer_data, NULL);
	TEST_ASSERT_EQUAL(-EINVAL, err);
}

void test_pds_peer_data_read(void)
{
	int err;
	uint16_t peer_id = 0;
	enum pm_peer_data_type data_type = PM_PEER_DATA_TYPE_BONDING;
	struct pm_peer_data peer_data = { 0 };
	size_t len;
	size_t expected_len = 10;

	__cmock_zms_evt_handler_set_IgnoreAndReturn(0);
	__cmock_zms_mount_IgnoreAndReturn(0);
	__cmock_peer_id_init_Ignore();

        for (uint16_t i = 0; i < CONFIG_PM_PEER_ID_N_AVAILABLE_IDS; i++) {
                __cmock_peer_id_alloc_ExpectAndReturn(i, 0);
        }

	err = pds_init();
	TEST_ASSERT_EQUAL(0, err);

	uint32_t entry_id = peer_id_peer_data_type_to_entry_id(peer_id, data_type);

	__cmock_zms_read_ExpectAndReturn(NULL, entry_id, peer_data.data, peer_data.len,
					 expected_len);
	__cmock_zms_read_IgnoreArg_fs();

	err = pds_peer_data_read(peer_id, data_type, &peer_data, &len);
	TEST_ASSERT_EQUAL(0, err);
	TEST_ASSERT_EQUAL(expected_len, len);
}

void test_pds_peer_data_store_eperm(void)
{
	int err;
	uint16_t peer_id = 0;
	struct pm_peer_data peer_data = {
		.data_type = PM_PEER_DATA_TYPE_BONDING,
	};

	err = pds_peer_data_store(peer_id, &peer_data);
	TEST_ASSERT_EQUAL(-EPERM, err);
}

void test_pds_peer_data_store_einval(void)
{
	int err;
	uint16_t peer_id = 0;
	uint16_t peer_id_invalid = PM_PEER_ID_INVALID;
	struct pm_peer_data peer_data = {
		.data_type = PM_PEER_DATA_TYPE_BONDING,
	};
	struct pm_peer_data peer_data_invalid = {
		.data_type = PM_PEER_DATA_TYPE_INVALID,
	};

	__cmock_zms_evt_handler_set_IgnoreAndReturn(0);
	__cmock_zms_mount_IgnoreAndReturn(0);
	__cmock_peer_id_init_Ignore();

        for (uint16_t i = 0; i < CONFIG_PM_PEER_ID_N_AVAILABLE_IDS; i++) {
                __cmock_peer_id_alloc_ExpectAndReturn(i, 0);
        }

	err = pds_init();
	TEST_ASSERT_EQUAL(0, err);

	err = pds_peer_data_store(peer_id_invalid, &peer_data);
	TEST_ASSERT_EQUAL(-EINVAL, err);

	err = pds_peer_data_store(peer_id, &peer_data_invalid);
	TEST_ASSERT_EQUAL(-EINVAL, err);

	err = pds_peer_data_store(peer_id, NULL);
	TEST_ASSERT_EQUAL(-EINVAL, err);
}

void test_pds_peer_data_store(void)
{
	int err;
	uint16_t peer_id = 0;
	struct pm_peer_data peer_data = {
		.data_type = PM_PEER_DATA_TYPE_BONDING,
		.len = 10
	};

	__cmock_zms_evt_handler_set_IgnoreAndReturn(0);
	__cmock_zms_mount_IgnoreAndReturn(0);
	__cmock_peer_id_init_Ignore();

        for (uint16_t i = 0; i < CONFIG_PM_PEER_ID_N_AVAILABLE_IDS; i++) {
                __cmock_peer_id_alloc_ExpectAndReturn(i, 0);
        }

	err = pds_init();
	TEST_ASSERT_EQUAL(0, err);

	uint32_t entry_id = peer_id_peer_data_type_to_entry_id(peer_id, peer_data.data_type);

	__cmock_zms_write_ExpectAndReturn(NULL, entry_id, peer_data.data, peer_data.len,
					  peer_data.len);
	__cmock_zms_write_IgnoreArg_fs();

	err = pds_peer_data_store(peer_id, &peer_data);
	TEST_ASSERT_EQUAL(0, err);
}

void test_pds_peer_data_delete_eperm(void)
{
	int err;
	uint16_t peer_id = 0;
	enum pm_peer_data_type data_type = PM_PEER_DATA_TYPE_BONDING;

	err = pds_peer_data_delete(peer_id, data_type);
	TEST_ASSERT_EQUAL(-EPERM, err);
}

void test_pds_peer_data_delete_einval(void)
{
	int err;
	uint16_t peer_id = 0;
	uint16_t peer_id_invalid = PM_PEER_ID_INVALID;
	enum pm_peer_data_type data_type = PM_PEER_DATA_TYPE_BONDING;
	enum pm_peer_data_type data_type_invalid = PM_PEER_DATA_TYPE_INVALID;

	__cmock_zms_evt_handler_set_IgnoreAndReturn(0);
	__cmock_zms_mount_IgnoreAndReturn(0);
	__cmock_peer_id_init_Ignore();

        for (uint16_t i = 0; i < CONFIG_PM_PEER_ID_N_AVAILABLE_IDS; i++) {
                __cmock_peer_id_alloc_ExpectAndReturn(i, 0);
        }

	err = pds_init();
	TEST_ASSERT_EQUAL(0, err);

	err = pds_peer_data_delete(peer_id_invalid, data_type);
	TEST_ASSERT_EQUAL(-EINVAL, err);

	err = pds_peer_data_delete(peer_id, data_type_invalid);
	TEST_ASSERT_EQUAL(-EINVAL, err);
}

void test_pds_peer_data_delete(void)
{
	int err;
	uint16_t peer_id = 0;
	enum pm_peer_data_type data_type = PM_PEER_DATA_TYPE_BONDING;

	__cmock_zms_evt_handler_set_IgnoreAndReturn(0);
	__cmock_zms_mount_IgnoreAndReturn(0);
	__cmock_peer_id_init_Ignore();

        for (uint16_t i = 0; i < CONFIG_PM_PEER_ID_N_AVAILABLE_IDS; i++) {
                __cmock_peer_id_alloc_ExpectAndReturn(i, 0);
        }

	err = pds_init();
	TEST_ASSERT_EQUAL(0, err);

	uint32_t entry_id = peer_id_peer_data_type_to_entry_id(peer_id, data_type);

	__cmock_zms_delete_ExpectAndReturn(NULL, entry_id, 0);
	__cmock_zms_delete_IgnoreArg_fs();

	err = pds_peer_data_delete(peer_id, data_type);
	TEST_ASSERT_EQUAL(0, err);
}

extern int unity_main(void);

int main(void)
{
	return unity_main();
}

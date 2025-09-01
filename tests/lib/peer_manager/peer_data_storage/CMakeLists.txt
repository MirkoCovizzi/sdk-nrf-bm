#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(unit_test_peer_data_storage)

add_compile_definitions(SVCALL_AS_NORMAL_FUNCTION=1)
add_compile_definitions(NRF54L15_XXAA)

# cmock_handle(${ZEPHYR_NRF_BM_MODULE_DIR}/lib/peer_manager/include/modules/peer_manager_internal.h)
# cmock_handle(${ZEPHYR_NRF_BM_MODULE_DIR}/lib/peer_manager/include/modules/peer_id.h)
# cmock_handle(${ZEPHYR_NRF_BM_MODULE_DIR}/include/bm_zms.h)

target_include_directories(app PRIVATE ${ZEPHYR_MODULE_DIR}/include/zephyr)
target_include_directories(app PRIVATE ${ZEPHYR_NRF_BM_MODULE_DIR}/include)
target_include_directories(app PRIVATE ${SOFTDEVICE_INCLUDE_DIR})
target_include_directories(app PRIVATE ${ZEPHYR_NRF_BM_MODULE_DIR}/lib/peer_manager/include)

target_compile_definitions(app PRIVATE
        CONFIG_PM_PEER_ID_N_AVAILABLE_IDS=256
)

# Generate and add test file
test_runner_generate(src/unity_test.c)
target_sources(app PRIVATE src/unity_test.c)

# Unit under test
target_sources(app PRIVATE ${ZEPHYR_NRF_BM_MODULE_DIR}/lib/peer_manager/modules/peer_data_storage.c)

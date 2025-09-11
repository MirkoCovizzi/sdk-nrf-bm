/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/sys/atomic.h>
typedef atomic_t nrf_mtx_t;

void nrf_mtx_init(nrf_mtx_t *p_mtx);
bool nrf_mtx_trylock(nrf_mtx_t *p_mtx);
void nrf_mtx_unlock(nrf_mtx_t *p_mtx);

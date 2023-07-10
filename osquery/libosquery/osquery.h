/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#if defined DLL_EXPORTS
#if defined WIN32
#define LIB_API(RetType) extern "C" __declspec(dllexport) RetType
#else
#define LIB_API(RetType)                                                       \
  extern "C" RetType __attribute__((visibility("default")))
#endif
#else
#if defined WIN32
#define LIB_API(RetType) extern "C" __declspec(dllimport) RetType
#else
#define LIB_API(RetType) extern "C" RetType
#endif
#endif

namespace osquery {
LIB_API(void) libosqueryInitialise();

LIB_API(char*) libosqueryQueryJson(const char* query, int* errorCode);

LIB_API(void) libosqueryFreeQueryResult(char* query);

LIB_API(void) libosqueryShutdown();
} // namespace osquery
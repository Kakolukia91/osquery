# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(libosqueryMain)
  generateLibosqueryFiles()
endfunction()

function(generateLibosqueryFiles)
  set(source_files
    osquery.cpp
  )  
  
  add_compile_definitions(DLL_EXPORTS)

  add_osquery_shared_library(libosquery ${source_files})

  set_target_properties(libosquery PROPERTIES PREFIX "")

  set(public_header_files
    osquery.h
  )
  generateIncludeNamespace(libosquery "osquery/libosquery" "FULL_PATH" ${public_header_files})

  target_link_libraries(libosquery PRIVATE
    osquery_core
    osquery_cxx_settings
    osquery_core_plugins
    osquery_database
    osquery_sql
    osquery_utils
    osquery_events    
    osquery_extensions
    osquery_extensions_implthrift
    osquery_remote_enroll_tlsenroll
    plugins_database_rocksdbplugin    
    osquery_carver
    osquery_distributed
    osquery_logger_datalogger
    osquery_process
    osquery_profiler    
    osquery_utils_conversions
    osquery_utils_info   
    plugins_config_tlsconfig     
    specs_tables
    thirdparty_boost    
    osquery_core_sql
    osquery_filesystem
    osquery_registry
    osquery_utils_system_env
    osquery_utils_system_systemutils
    osquery_utils_system_time
    osquery_logger
    thirdparty_gflags
    thirdparty_glog
    thirdparty_openssl
    thirdparty_sqlite    
  )
endfunction()

function(enableLibOsqueryWEL)
  target_sources(libosquery PRIVATE "${TOOLS_WEL_FILES_ROOT_DIR}/windows_resources.rc")
endfunction()

libosqueryMain()

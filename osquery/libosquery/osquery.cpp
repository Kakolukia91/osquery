/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "osquery.h"

#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/hashing/hashing.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/utils/system/time.h>
#include <plugins/database/rocksdb.h>

#ifdef OSQUERY_WINDOWS
#include <osquery/core/windows/global_users_groups_cache.h>
#include <osquery/system/usersgroups/windows/groups_service.h>
#include <osquery/system/usersgroups/windows/users_service.h>
#endif

namespace osquery {
DECLARE_string(config_plugin);
DECLARE_string(logger_plugin);
DECLARE_string(numeric_monitoring_plugins);
DECLARE_string(distributed_plugin);
DECLARE_bool(config_check);
DECLARE_bool(config_dump);
DECLARE_bool(database_dump);
DECLARE_string(database_path);
DECLARE_bool(disable_distributed);
DECLARE_bool(disable_database);
DECLARE_bool(disable_events);
DECLARE_bool(disable_logging);
DECLARE_bool(enable_numeric_monitoring);
DECLARE_bool(ignore_table_exceptions);
DECLARE_bool(ignore_registry_exceptions);

Status sqlQueryToJson(const std::string& name,
                      const std::string& querySql,
                      std::string& jsonResult) {
  jsonResult = "";

  auto sql = SQLInternal(querySql, true);
  if (!sql.getStatus().ok()) {
    return Status::failure("Error executing scheduled query");
  }

  QueryDataTyped queryData = sql.rowsTyped();
  for (auto& rows : queryData) {
    std::ostringstream allColumnValues;
    for (const auto& col : rows) {
      allColumnValues << col.second;
    }
    const std::string& toHash = allColumnValues.str();
    rows["Hash"] = hashFromBuffer(HASH_TYPE_MD5, toHash.c_str(), toHash.size());
  }

  Status status = serializeQueryDataJSON(queryData, jsonResult, true);

  return status;
}
} // namespace osquery

namespace osquery {
void libosqueryInitialise(const char* databasePath) {
  FLAGS_ignore_table_exceptions = true;
  FLAGS_ignore_registry_exceptions = true;
  FLAGS_disable_logging = true;

  FLAGS_database_path = databasePath;

#ifdef OSQUERY_WINDOWS
  std::promise<void> users_cache_promise;
  GlobalUsersGroupsCache::global_users_cache_future_ =
      users_cache_promise.get_future();

  Dispatcher::addService(std::make_shared<UsersService>(
      std::move(users_cache_promise),
      GlobalUsersGroupsCache::global_users_cache_));

  std::promise<void> groups_cache_promise;
  GlobalUsersGroupsCache::global_groups_cache_future_ =
      groups_cache_promise.get_future();

  Dispatcher::addService(std::make_shared<GroupsService>(
      std::move(groups_cache_promise),
      GlobalUsersGroupsCache::global_groups_cache_));
#endif

  platformSetup();
  registryAndPluginInit();

  setDatabaseAllowOpen();
  initDatabasePlugin();
  upgradeDatabase();
  resetDatabase();
  Registry::setUp();
}

void libosqueryShutdown() {
#ifdef OSQUERY_WINDOWS
  Dispatcher::stopServices();
  Dispatcher::joinServices();
#endif

  shutdownDatabase();
  platformTeardown();

#ifdef OSQUERY_WINDOWS
  GlobalUsersGroupsCache::global_users_cache_->clear();
  GlobalUsersGroupsCache::global_users_cache_future_ = {};

  GlobalUsersGroupsCache::global_groups_cache_->clear();
  GlobalUsersGroupsCache::global_groups_cache_future_ = {};
#endif
}

char* libosqueryQueryJson(const char* queryName,
                          const char* querySql,
                          int* errorCode) {
  std::string jsonResult;
  Status status =
      sqlQueryToJson(std::string(queryName), std::string(querySql), jsonResult);

  char* result = nullptr;

  if (status.ok() && !jsonResult.empty()) {
    const std::size_t queryJsonLen = jsonResult.size();

    result = (char*)malloc(queryJsonLen + 1);
    std::strcpy(result, jsonResult.c_str());
  }

  if (errorCode) {
    *errorCode = status.getCode();
  }

  return result;
}

void libosqueryFreeQueryResult(char* query) {
  if (query) {
    free(query);
  }
}
} // namespace osquery

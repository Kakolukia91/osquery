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
#include <osquery/hashing/hashing.h>
#include <osquery/database/database.h>
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
Status sqlQueryToJson(const std::string& name,
                      const std::string& querySql,
                      std::string& jsonResult) {
  jsonResult = "";

  auto sql = SQLInternal(querySql, true);
  if (!sql.getStatus().ok()) {
    return Status::failure("Error executing scheduled query");
  }

  std::string ident = getHostIdentifier();

  QueryLogItem item;
  item.name = name;
  item.identifier = ident;
  item.time = osquery::getUnixTime();
  item.epoch = 0;
  item.calendar_time = osquery::getAsciiTime();
  item.isSnapshot = false;

  // Set counter to 1 here to be able to tell if this was a new epoch
  // (counter=0) in the differential stream. Whenever actually logging
  // results below, this counter value will have been overwritten in
  // addNewResults.
  item.counter = 1;

  // Create a database-backed set of query results.
  auto dbQuery = Query(name, querySql);
  // Comparisons and stores must include escaped data.
  sql.escapeResults();
  Status status;
  DiffResults& diff_results = item.results;
  // Add this execution's set of results to the database-tracked named query.
  // We can then ask for a differential from the last time this named query
  // was executed by exact matching each row.
  status = dbQuery.addNewResults(
      std::move(sql.rowsTyped()), item.epoch, item.counter, diff_results);

  if (!status.ok()) {
    return status;
  }

  if (diff_results.hasNoResults()) {
    // No diff results to set
    return status;
  }

  for (auto& removed : diff_results.removed) {
    std::ostringstream allColumnValues;
    for (const auto& col : removed) {
      allColumnValues << col.second;
    }
    const std::string& toHash = allColumnValues.str();
    removed["Hash"] = hashFromBuffer(HASH_TYPE_MD5, toHash.c_str(), toHash.size());
  }

  for (auto& added : diff_results.added) {
    std::ostringstream allColumnValues;
    for (const auto& col : added) {
      allColumnValues << col.second;
    }
    const std::string& toHash = allColumnValues.str();
    added["Hash"] = hashFromBuffer(HASH_TYPE_MD5, toHash.c_str(), toHash.size());
  }  

  status = serializeQueryLogItemJSON(item, jsonResult);

  return status;
}
} // namespace osquery

namespace osquery {
void libosqueryInitialise(const char* databasePath) {
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

  setDatabasePath(databasePath);

  platformSetup();
  registryAndPluginInit();

  setDatabaseAllowOpen();
  initDatabasePlugin();
  resetDatabase();
}

void libosqueryShutdown() {
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

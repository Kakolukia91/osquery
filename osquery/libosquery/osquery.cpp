#include "osquery.h"

#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sqlite_util.h>

#ifdef OSQUERY_WINDOWS
#include <osquery/core/windows/global_users_groups_cache.h>
#include <osquery/system/usersgroups/windows/groups_service.h>
#include <osquery/system/usersgroups/windows/users_service.h>
#endif

namespace osquery {
void libosqueryInitialise() {
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

char* libosqueryQueryJson(const char* query, int* errorCode) {
  auto instance = SQLiteDBManager::get();

  QueryData rows;
  Status status = queryInternal(query, rows, instance);

  char* result = nullptr;

  if (status.ok()) {
    std::string queryJson;
    status = serializeQueryDataJSON(rows, queryJson);

    if (status.ok()) {
      const std::size_t queryJsonLen = queryJson.size();

      result = (char*)malloc(queryJsonLen + 1);

      strncpy_s(result, queryJsonLen + 1, queryJson.c_str(), queryJsonLen);
      result[queryJsonLen] = '\0';
    }
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

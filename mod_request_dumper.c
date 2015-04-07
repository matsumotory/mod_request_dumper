#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_log.h"
#include "apr_strings.h"

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <json.h>

#define MOD_STLOG_FILE        "/tmp/mod_request_dumper.log"
#define MODULE_NAME           "mod_request_dumper"
#define MODULE_VERSION        "0.0.1"
#define ON                    1
#define OFF                   0

#if (AP_SERVER_MINORVERSION_NUMBER > 2)
  #define __APACHE24__
#endif

typedef struct stlog_dir_config {

    char *log_filename;
    int translate_name_phase;
    int post_read_request_phase;
    int map_to_storage_phase;
    int check_user_id_phase;
    int type_checker_phase;
    int access_checker_phase;
    int auth_checker_phase;
    int insert_filter_phase;
    int fixups_phase;
    int quick_handler_phase;
    int handler_phase;
    int log_transaction_phase;
    int error_log_phase;

} stlog_config_t;

module AP_MODULE_DECLARE_DATA request_dumper_module;
apr_file_t *mod_stlog_fp = NULL;

static const char *ap_mrb_string_check(apr_pool_t *p, const char *str)
{
    char *val;

    if (str == NULL) {
        val = apr_pstrdup(p, "null");
        return val;
    }

    return str;
}

static json_object *ap_stlog_remote_addr_to_json(request_rec *r)
{
    json_object *my_object;

    my_object = json_object_new_object();
#ifdef __APACHE24__
    json_object_object_add(my_object, "hostname", json_object_new_string(ap_mrb_string_check(r->pool, r->connection->client_addr->hostname)));
#else
    json_object_object_add(my_object, "hostname", json_object_new_string(ap_mrb_string_check(r->pool, r->connection->remote_addr->hostname)));
#endif

#ifdef __APACHE24__
    json_object_object_add(my_object, "port", json_object_new_int(r->connection->client_addr->port));
#else
    json_object_object_add(my_object, "port", json_object_new_int(r->connection->remote_addr->port));
#endif

    return my_object;
}

static json_object *ap_stlog_local_addr_to_json(request_rec *r)
{
    json_object *my_object;

    my_object = json_object_new_object();
    json_object_object_add(my_object, "hostname", json_object_new_string(ap_mrb_string_check(r->pool, r->connection->local_addr->hostname)));

    json_object_object_add(my_object, "port", json_object_new_int(r->connection->local_addr->port));

    return my_object;
}

static json_object *ap_stlog_conn_rec_to_json(request_rec *r)
{
    json_object *my_object;

    my_object = json_object_new_object();
#ifdef __APACHE24__
    json_object_object_add(my_object, "remote_ip", json_object_new_string(ap_mrb_string_check(r->pool, r->connection->client_ip)));
#else
    json_object_object_add(my_object, "remote_ip", json_object_new_string(ap_mrb_string_check(r->pool, r->connection->remote_ip)));
#endif
    json_object_object_add(my_object, "remote_host", json_object_new_string(ap_mrb_string_check(r->pool, r->connection->remote_host)));
    json_object_object_add(my_object, "remote_logname", json_object_new_string(ap_mrb_string_check(r->pool, r->connection->remote_logname)));
    json_object_object_add(my_object, "local_ip", json_object_new_string(ap_mrb_string_check(r->pool, r->connection->local_ip)));
    json_object_object_add(my_object, "local_host", json_object_new_string(ap_mrb_string_check(r->pool, r->connection->local_host)));

    json_object_object_add(my_object, "keepalives", json_object_new_int(r->connection->keepalives));
    json_object_object_add(my_object, "data_in_input_filters", json_object_new_int(r->connection->data_in_input_filters));

    json_object_object_add(my_object, "local_addr", ap_stlog_local_addr_to_json(r));
    json_object_object_add(my_object, "remote_addr", ap_stlog_remote_addr_to_json(r));

    return my_object;
}

static json_object *ap_stlog_process_rec_to_json(request_rec *r)
{
    json_object *my_object;

    my_object = json_object_new_object();
    json_object_object_add(my_object, "short_name", json_object_new_string(ap_mrb_string_check(r->pool, r->server->process->short_name)));
    //json_object_object_add(my_object, "argv", json_object_new_string(ap_mrb_string_check(r->pool, (char *)r->server->process->argv)));
    json_object_object_add(my_object, "argc", json_object_new_int(r->server->process->argc));

    return my_object;
}

static json_object *ap_stlog_host_addr_to_json(request_rec *r)
{
    json_object *my_object;

    my_object = json_object_new_object();
    json_object_object_add(my_object, "hostname", json_object_new_string(ap_mrb_string_check(r->pool, r->server->addrs->host_addr->hostname)));

    json_object_object_add(my_object, "port", json_object_new_int(r->server->addrs->host_addr->port));

    return my_object;
}


static json_object *ap_stlog_server_addr_rec_to_json(request_rec *r)
{
    json_object *my_object;

    my_object = json_object_new_object();
    json_object_object_add(my_object, "virthost", json_object_new_string(ap_mrb_string_check(r->pool, r->server->addrs->virthost)));

    json_object_object_add(my_object, "host_port", json_object_new_int(r->server->addrs->host_port));

    json_object_object_add(my_object, "host_addr", ap_stlog_host_addr_to_json(r));

    return my_object;
}

static json_object *ap_stlog_server_rec_to_json(request_rec *r)
{
    json_object *my_object;

    my_object = json_object_new_object();
    json_object_object_add(my_object, "error_fname", json_object_new_string(ap_mrb_string_check(r->pool, r->server->error_fname)));
    json_object_object_add(my_object, "defn_name", json_object_new_string(ap_mrb_string_check(r->pool, r->server->defn_name)));
    json_object_object_add(my_object, "server_scheme", json_object_new_string(ap_mrb_string_check(r->pool, r->server->server_scheme)));
    json_object_object_add(my_object, "server_admin", json_object_new_string(ap_mrb_string_check(r->pool, r->server->server_admin)));
    json_object_object_add(my_object, "path", json_object_new_string(ap_mrb_string_check(r->pool, r->server->path)));
    json_object_object_add(my_object, "server_hostname", json_object_new_string(ap_mrb_string_check(r->pool, r->server->server_hostname)));

#ifndef __APACHE24__
    json_object_object_add(my_object, "loglevel", json_object_new_int(r->server->loglevel));
#endif
    json_object_object_add(my_object, "is_virtual", json_object_new_int(r->server->is_virtual));
    json_object_object_add(my_object, "keep_alive_max", json_object_new_int(r->server->keep_alive_max));
    json_object_object_add(my_object, "keep_alive", json_object_new_int(r->server->keep_alive));
    json_object_object_add(my_object, "pathlen", json_object_new_int(r->server->pathlen));
    json_object_object_add(my_object, "limit_req_line", json_object_new_int(r->server->limit_req_line));
    json_object_object_add(my_object, "limit_req_fieldsize", json_object_new_int(r->server->limit_req_fieldsize));
    json_object_object_add(my_object, "limit_req_fields", json_object_new_int(r->server->limit_req_fields));
    json_object_object_add(my_object, "limit_req_fields", json_object_new_int(r->server->limit_req_fields));
    json_object_object_add(my_object, "timeout", json_object_new_int((int)r->server->timeout));
    json_object_object_add(my_object, "keep_alive_timeout", json_object_new_int((int)r->server->keep_alive_timeout));
    json_object_object_add(my_object, "port", json_object_new_int((int)r->server->port));
    json_object_object_add(my_object, "defn_line_number", json_object_new_int((int)r->server->defn_line_number));

    json_object_object_add(my_object, "process", ap_stlog_process_rec_to_json(r));
    json_object_object_add(my_object, "addrs", ap_stlog_server_addr_rec_to_json(r));

    return my_object;
}

/*
static json_object *ap_stlog_htaccess_result_to_json(request_rec *r)
{
    json_object *my_object;

    my_object = json_object_new_object();
    json_object_object_add(my_object, "dir", json_object_new_string(ap_mrb_string_check(r->pool, r->htaccess->dir)));
    json_object_object_add(my_object, "override", json_object_new_int(r->htaccess->override));
    json_object_object_add(my_object, "override_opts", json_object_new_int(r->htaccess->override_opts));

    return my_object;
}
*/

static json_object *ap_stlog_headers_out_to_json(request_rec *r)
{
    json_object *my_object;
    int i;

    my_object = json_object_new_object();
    const apr_array_header_t *arr = apr_table_elts(r->headers_out);
    apr_table_entry_t *elts = (apr_table_entry_t *)arr->elts;
    for (i = 0; i < arr->nelts; i++) {
        json_object_object_add(my_object, elts[i].key, json_object_new_string(ap_mrb_string_check(r->pool, elts[i].val)));
    }

    return my_object;
}

static json_object *ap_stlog_headers_in_to_json(request_rec *r)
{
    json_object *my_object;
    int i;

    my_object = json_object_new_object();
    const apr_array_header_t *arr = apr_table_elts(r->headers_in);
    apr_table_entry_t *elts = (apr_table_entry_t *)arr->elts;
    for (i = 0; i < arr->nelts; i++) {
        json_object_object_add(my_object, elts[i].key, json_object_new_string(ap_mrb_string_check(r->pool, elts[i].val)));
    }

    return my_object;
}

static json_object *ap_stlog_request_rec_to_json(request_rec *r)
{
    json_object *my_object;

    my_object = json_object_new_object();
    json_object_object_add(my_object, "filename", json_object_new_string(ap_mrb_string_check(r->pool, r->filename)));
    json_object_object_add(my_object, "uri", json_object_new_string(ap_mrb_string_check(r->pool, r->uri)));
    json_object_object_add(my_object, "user", json_object_new_string(ap_mrb_string_check(r->pool, r->user)));
    json_object_object_add(my_object, "content_type", json_object_new_string(ap_mrb_string_check(r->pool, r->content_type)));
    json_object_object_add(my_object, "protocol", json_object_new_string(ap_mrb_string_check(r->pool, r->protocol)));
    json_object_object_add(my_object, "vlist_validator", json_object_new_string(ap_mrb_string_check(r->pool, r->vlist_validator)));
    json_object_object_add(my_object, "ap_auth_type", json_object_new_string(ap_mrb_string_check(r->pool, r->ap_auth_type)));
    json_object_object_add(my_object, "unparsed_uri", json_object_new_string(ap_mrb_string_check(r->pool, r->unparsed_uri)));
    json_object_object_add(my_object, "canonical_filename", json_object_new_string(ap_mrb_string_check(r->pool, r->canonical_filename)));
    json_object_object_add(my_object, "path_info", json_object_new_string(ap_mrb_string_check(r->pool, r->path_info)));
    json_object_object_add(my_object, "hostname", json_object_new_string(ap_mrb_string_check(r->pool, r->hostname)));
    json_object_object_add(my_object, "method", json_object_new_string(ap_mrb_string_check(r->pool, r->method)));
    json_object_object_add(my_object, "the_request", json_object_new_string(ap_mrb_string_check(r->pool, r->the_request)));
    json_object_object_add(my_object, "range", json_object_new_string(ap_mrb_string_check(r->pool, r->range)));
    json_object_object_add(my_object, "handler", json_object_new_string(ap_mrb_string_check(r->pool, r->handler)));
    json_object_object_add(my_object, "args", json_object_new_string(ap_mrb_string_check(r->pool, r->args)));
    json_object_object_add(my_object, "status_line", json_object_new_string(ap_mrb_string_check(r->pool, r->status_line)));
    json_object_object_add(my_object, "content_encoding", json_object_new_string(ap_mrb_string_check(r->pool, r->content_encoding)));

    json_object_object_add(my_object, "assbackwards", json_object_new_int(r->assbackwards));
    json_object_object_add(my_object, "proxyreq", json_object_new_int(r->proxyreq));
    json_object_object_add(my_object, "header_only", json_object_new_int(r->header_only));
    json_object_object_add(my_object, "proto_num", json_object_new_int(r->proto_num));
    json_object_object_add(my_object, "status", json_object_new_int(r->status));
    json_object_object_add(my_object, "method_number", json_object_new_int(r->method_number));
    json_object_object_add(my_object, "chunked", json_object_new_int(r->chunked));
    json_object_object_add(my_object, "read_body", json_object_new_int(r->read_body));
    json_object_object_add(my_object, "read_chunked", json_object_new_int(r->read_chunked));
    json_object_object_add(my_object, "no_cache", json_object_new_int(r->no_cache));
    json_object_object_add(my_object, "no_local_copy", json_object_new_int(r->no_local_copy));
    json_object_object_add(my_object, "used_path_info", json_object_new_int(r->used_path_info));
    json_object_object_add(my_object, "eos_sent", json_object_new_int(r->eos_sent));
    json_object_object_add(my_object, "request_time", json_object_new_int(r->request_time));

    json_object_object_add(my_object, "connection", ap_stlog_conn_rec_to_json(r));
    json_object_object_add(my_object, "server", ap_stlog_server_rec_to_json(r));
    json_object_object_add(my_object, "headers_in", ap_stlog_headers_in_to_json(r));
    json_object_object_add(my_object, "headers_out", ap_stlog_headers_out_to_json(r));
    //json_object_object_add(my_object, "htaccess", ap_stlog_htaccess_result_to_json(r));

    return my_object;
}

void mod_stlog_logging(json_object *json_obj, const char *func, apr_pool_t *p)
{
    int len;
    time_t t;
    char *log_time, *val;
    char *mod_stlog_buf = NULL;

    time(&t);
    log_time = (char *)ctime(&t);
    len = strlen(log_time);
    log_time[len - 1] = '\0';

    json_object_object_add(json_obj, "time", json_object_new_string(ap_mrb_string_check(p, log_time)));
    json_object_object_add(json_obj, "pid", json_object_new_int(getpid()));
    json_object_object_add(json_obj, "hook", json_object_new_string(ap_mrb_string_check(p, func)));

    val = (char *)json_object_to_json_string(json_obj);

    mod_stlog_buf = (char *)apr_psprintf(p, "%s\n", val);

    apr_file_puts(mod_stlog_buf, mod_stlog_fp);
    apr_file_flush(mod_stlog_fp);
}


static int mod_stlog_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *server)
{
    stlog_config_t *conf = ap_get_module_config(server->module_config, &request_dumper_module);

    if (*conf->log_filename == '|') {
        piped_log *pl;

        pl = ap_open_piped_log(p, conf->log_filename + 1);
        if (pl == NULL) {
            ap_log_error(APLOG_MARK
                , APLOG_ERR
                , 0
                , NULL
                , "%s ERROR %s: dump pipe log oepn failed: %s"
                , MODULE_NAME
                , __func__
                , conf->log_filename
            );

            return OK;
        }

        mod_stlog_fp = ap_piped_log_write_fd(pl);

    } else {
        if(apr_file_open(&mod_stlog_fp, conf->log_filename, APR_WRITE|APR_APPEND|APR_CREATE,
               APR_OS_DEFAULT, p) != APR_SUCCESS){
            ap_log_error(APLOG_MARK
                , APLOG_ERR
                , 0
                , NULL
                , "%s ERROR %s: dump log file oepn failed: %s"
                , MODULE_NAME
                , __func__
                , conf->log_filename
            );

            return OK;
        }
    }

    ap_log_perror(APLOG_MARK
        , APLOG_NOTICE
        , 0
        , p
        , "%s %s: %s / %s mechanism enabled."
        , MODULE_NAME
        , __func__
        , MODULE_NAME
        , MODULE_VERSION
    );

    return OK;
}

static void *mod_stlog_create_config(apr_pool_t *p, server_rec *s)
{
    stlog_config_t *conf =
        (stlog_config_t *) apr_pcalloc(p, sizeof (*conf));

    conf->log_filename              = apr_pstrdup(p, MOD_STLOG_FILE);
    conf->post_read_request_phase   = OFF;
    conf->translate_name_phase      = OFF;
    conf->map_to_storage_phase      = OFF;
    conf->check_user_id_phase       = OFF;
    conf->type_checker_phase        = OFF;
    conf->access_checker_phase      = OFF;
    conf->auth_checker_phase        = OFF;
    conf->insert_filter_phase       = OFF;
    conf->fixups_phase              = OFF;
    conf->quick_handler_phase       = OFF;
    conf->handler_phase             = OFF;
    conf->log_transaction_phase     = OFF;
    conf->error_log_phase           = OFF;

    return conf;
}

static int mod_stlog_post_read_request(request_rec *r)
{
    stlog_config_t *conf = ap_get_module_config(r->server->module_config, &request_dumper_module);
    if (conf->post_read_request_phase == ON)
        mod_stlog_logging(ap_stlog_request_rec_to_json(r), "ap_hook_post_read_request", r->pool);
    return DECLINED;
}

static int mod_stlog_map_to_storage(request_rec *r)
{
    stlog_config_t *conf = ap_get_module_config(r->server->module_config, &request_dumper_module);
    if (conf->map_to_storage_phase == ON)
        mod_stlog_logging(ap_stlog_request_rec_to_json(r), "ap_hook_map_to_storage", r->pool);
    return DECLINED;
}

static int mod_stlog_check_user_id(request_rec *r)
{
    stlog_config_t *conf = ap_get_module_config(r->server->module_config, &request_dumper_module);
    if (conf->check_user_id_phase == ON)
        mod_stlog_logging(ap_stlog_request_rec_to_json(r), "ap_hook_check_user_id", r->pool);
    return DECLINED;
}

static int mod_stlog_type_checker(request_rec *r)
{
    stlog_config_t *conf = ap_get_module_config(r->server->module_config, &request_dumper_module);
    if (conf->type_checker_phase == ON)
        mod_stlog_logging(ap_stlog_request_rec_to_json(r), "ap_hook_type_checker", r->pool);
    return DECLINED;
}

static int mod_stlog_access_checker(request_rec *r)
{
    stlog_config_t *conf = ap_get_module_config(r->server->module_config, &request_dumper_module);
    if (conf->access_checker_phase == ON)
        mod_stlog_logging(ap_stlog_request_rec_to_json(r), "ap_hook_access_checker", r->pool);
    return DECLINED;
}

static int mod_stlog_auth_checker(request_rec *r)
{
    stlog_config_t *conf = ap_get_module_config(r->server->module_config, &request_dumper_module);
    if (conf->auth_checker_phase == ON)
        mod_stlog_logging(ap_stlog_request_rec_to_json(r), "ap_hook_auth_checker", r->pool);
    return DECLINED;
}

static void mod_stlog_insert_filter(request_rec *r)
{
    stlog_config_t *conf = ap_get_module_config(r->server->module_config, &request_dumper_module);
    if (conf->insert_filter_phase == ON)
        mod_stlog_logging(ap_stlog_request_rec_to_json(r), "ap_hook_insert_filter", r->pool);
    //return DECLINED;
}

static int mod_stlog_fixups(request_rec *r)
{
    stlog_config_t *conf = ap_get_module_config(r->server->module_config, &request_dumper_module);
    if (conf->fixups_phase == ON)
        mod_stlog_logging(ap_stlog_request_rec_to_json(r), "ap_hook_fixups", r->pool);
    return DECLINED;
}

static int mod_stlog_quick_handler(request_rec *r, int lookup)
{
    stlog_config_t *conf = ap_get_module_config(r->server->module_config, &request_dumper_module);
    if (conf->quick_handler_phase == ON)
        mod_stlog_logging(ap_stlog_request_rec_to_json(r), "ap_hook_quick_handler", r->pool);
    return DECLINED;
}

/*
static int mod_stlog_error_log(request_rec *rp)
{
    stlog_config_t *conf = ap_get_module_config(r->server->module_config, &request_dumper_module);
    if (conf->error_log_phase == ON)
        mod_stlog_logging(ap_stlog_request_rec_to_json(r), "ap_hook_error_log", r->pool);
    return DECLINED;
}
*/

static int mod_stlog_handler(request_rec *r)
{
    stlog_config_t *conf = ap_get_module_config(r->server->module_config, &request_dumper_module);
    if (conf->handler_phase == ON)
        mod_stlog_logging(ap_stlog_request_rec_to_json(r), "ap_hook_handler", r->pool);
    return DECLINED;
}

static int mod_stlog_translate_name(request_rec *r)
{
    stlog_config_t *conf = ap_get_module_config(r->server->module_config, &request_dumper_module);
    if (conf->translate_name_phase == ON)
        mod_stlog_logging(ap_stlog_request_rec_to_json(r), "ap_hook_translate_name", r->pool);
    return DECLINED;
}

static int mod_stlog_log_transaction(request_rec *r)
{
    stlog_config_t *conf = ap_get_module_config(r->server->module_config, &request_dumper_module);
    if (conf->log_transaction_phase == ON)
        mod_stlog_logging(ap_stlog_request_rec_to_json(r), "ap_hook_log_transaction", r->pool);
    return DECLINED;
}


static const char *set_stlog_logname(cmd_parms *cmd, void *mconfig, const char *log_filename)
{
    stlog_config_t *conf = ap_get_module_config(cmd->server->module_config, &request_dumper_module);
    conf->log_filename = apr_pstrdup(cmd->pool, log_filename);
    return NULL;
}

static const char *set_stlog_post_read_request(cmd_parms *cmd, void *mconfig, int dump_on)
{
    stlog_config_t *conf = ap_get_module_config(cmd->server->module_config, &request_dumper_module);
    conf->post_read_request_phase = dump_on;
    return NULL;
}

static const char *set_stlog_map_to_storage(cmd_parms *cmd, void *mconfig, int dump_on)
{
    stlog_config_t *conf = ap_get_module_config(cmd->server->module_config, &request_dumper_module);
    conf->map_to_storage_phase = dump_on;
    return NULL;
}

static const char *set_stlog_check_user_id(cmd_parms *cmd, void *mconfig, int dump_on)
{
    stlog_config_t *conf = ap_get_module_config(cmd->server->module_config, &request_dumper_module);
    conf->check_user_id_phase = dump_on;
    return NULL;
}

static const char *set_stlog_type_checker(cmd_parms *cmd, void *mconfig, int dump_on)
{
    stlog_config_t *conf = ap_get_module_config(cmd->server->module_config, &request_dumper_module);
    conf->type_checker_phase = dump_on;
    return NULL;
}

static const char *set_stlog_access_checker(cmd_parms *cmd, void *mconfig, int dump_on)
{
    stlog_config_t *conf = ap_get_module_config(cmd->server->module_config, &request_dumper_module);
    conf->access_checker_phase = dump_on;
    return NULL;
}

static const char *set_stlog_auth_checker(cmd_parms *cmd, void *mconfig, int dump_on)
{
    stlog_config_t *conf = ap_get_module_config(cmd->server->module_config, &request_dumper_module);
    conf->auth_checker_phase = dump_on;
    return NULL;
}

static const char *set_stlog_insert_filter(cmd_parms *cmd, void *mconfig, int dump_on)
{
    stlog_config_t *conf = ap_get_module_config(cmd->server->module_config, &request_dumper_module);
    conf->insert_filter_phase = dump_on;
    return NULL;
}

static const char *set_stlog_fixups(cmd_parms *cmd, void *mconfig, int dump_on)
{
    stlog_config_t *conf = ap_get_module_config(cmd->server->module_config, &request_dumper_module);
    conf->fixups_phase = dump_on;
    return NULL;
}

static const char *set_stlog_quick_handler(cmd_parms *cmd, void *mconfig, int dump_on)
{
    stlog_config_t *conf = ap_get_module_config(cmd->server->module_config, &request_dumper_module);
    conf->quick_handler_phase = dump_on;
    return NULL;
}

/*
static const char *set_stlog_error_log(cmd_parms *cmd, void *mconfig, int dump_on)
{
    stlog_config_t *conf = ap_get_module_config(cmd->server->module_config, &request_dumper_module);
    conf->error_log_phase = dump_on;
    return NULL;
}
*/

static const char *set_stlog_handler(cmd_parms *cmd, void *mconfig, int dump_on)
{
    stlog_config_t *conf = ap_get_module_config(cmd->server->module_config, &request_dumper_module);
    conf->handler_phase = dump_on;
    return NULL;
}

static const char *set_stlog_translate_name(cmd_parms *cmd, void *mconfig, int dump_on)
{
    stlog_config_t *conf = ap_get_module_config (cmd->server->module_config, &request_dumper_module);
    conf->translate_name_phase = dump_on;
    return NULL;
}

static const char *set_stlog_log_transaction(cmd_parms *cmd, void *mconfig, int dump_on)
{
    stlog_config_t *conf = ap_get_module_config (cmd->server->module_config, &request_dumper_module);
    conf->log_transaction_phase = dump_on;
    return NULL;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(mod_stlog_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(mod_stlog_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_translate_name(mod_stlog_translate_name, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_map_to_storage(mod_stlog_map_to_storage, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id(mod_stlog_check_user_id, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_type_checker(mod_stlog_type_checker, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_access_checker(mod_stlog_access_checker, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_auth_checker(mod_stlog_auth_checker, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_insert_filter(mod_stlog_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(mod_stlog_fixups, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_quick_handler(mod_stlog_quick_handler, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_handler(mod_stlog_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_log_transaction(mod_stlog_log_transaction, NULL, NULL, APR_HOOK_MIDDLE);
    //ap_hook_error_log(mod_stlog_error_log, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec mod_stlog_cmds[] = {

    AP_INIT_TAKE1("DumpRequestLog", set_stlog_logname, NULL, RSRC_CONF | ACCESS_CONF, "Dumping log name."),
    AP_INIT_FLAG("DumpPostReadRequest", set_stlog_post_read_request, NULL, RSRC_CONF | ACCESS_CONF, "hook for post_read_request phase."),
    AP_INIT_FLAG("DumpTranslateName", set_stlog_translate_name, NULL, RSRC_CONF | ACCESS_CONF, "hook for translate_name phase."),
    AP_INIT_FLAG("DumpMapToStorage", set_stlog_map_to_storage, NULL, RSRC_CONF | ACCESS_CONF, "hook for map_to_storage phase."),
    AP_INIT_FLAG("DumpCheckUserId", set_stlog_check_user_id, NULL, RSRC_CONF | ACCESS_CONF, "hook for check_user_id phase."),
    AP_INIT_FLAG("DumpTypeChecker", set_stlog_type_checker, NULL, RSRC_CONF | ACCESS_CONF, "hook for type_checker phase."),
    AP_INIT_FLAG("DumpAccessChecker", set_stlog_access_checker, NULL, RSRC_CONF | ACCESS_CONF, "hook for access_checker phase."),
    AP_INIT_FLAG("DumpAuthChecker", set_stlog_auth_checker, NULL, RSRC_CONF | ACCESS_CONF, "hook for auth_checker phase."),
    AP_INIT_FLAG("DumpInsertFilter", set_stlog_insert_filter, NULL, RSRC_CONF | ACCESS_CONF, "hook for insert_filter phase."),
    AP_INIT_FLAG("DumpFixups", set_stlog_fixups, NULL, RSRC_CONF | ACCESS_CONF, "hook for fixups phase."),
    AP_INIT_FLAG("DumpQuickHandler", set_stlog_quick_handler, NULL, RSRC_CONF | ACCESS_CONF, "hook for quick_handler phase."),
    AP_INIT_FLAG("DumpHandler", set_stlog_handler, NULL, RSRC_CONF | ACCESS_CONF, "hook for handler phase."),
    AP_INIT_FLAG("DumpLogTransaction", set_stlog_log_transaction, NULL, RSRC_CONF | ACCESS_CONF, "hook for log_transaction phase."),
    //AP_INIT_FLAG("DumpErrorLog", set_stlog_error_log, NULL, RSRC_CONF | ACCESS_CONF, "hook for error_log phase."),
    {NULL}
};

module AP_MODULE_DECLARE_DATA request_dumper_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                      /* dir config creater */
    NULL,                      /* dir merger */
    mod_stlog_create_config,   /* server config */
    NULL,                      /* merge server config */
    mod_stlog_cmds,            /* command apr_table_t */
    register_hooks             /* register hooks */
};

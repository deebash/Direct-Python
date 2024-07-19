/* 
 * Direct Python (from deebash.org) project started with Helloworld template
 * configured in apache.conf as below
 * 
 * LoadModule directpython_module modules/mod_dp.so
 * AddHandler directpython .dp
 *
 * Compile by: 
 *    $ apxs -c -i mod_dp.c
 * APXS compiles and loads module into Apache by default. 
 * Just restart your apache for changes to take effect.
 * sudo systemctl restart apache2
 * 
 * Debug commands
 * sudo apache2ctl configtest
 */ 

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_pools.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>

typedef struct {
    FILE *input;
    FILE *output;
    pid_t pid;
} python_subprocess_t;

python_subprocess_t *start_python_subprocess(request_rec *r) {
    int input_pipe[2];
    int output_pipe[2];

    if (pipe(input_pipe) == -1 || pipe(output_pipe) == -1) {
        ap_rprintf(r, "Error creating pipes\n");
        return NULL;
    }

    pid_t pid = fork();
    if (pid == -1) {
        ap_rprintf(r, "Error forking process\n");
        return NULL;
    }

    if (pid == 0) {
        close(input_pipe[1]);
        close(output_pipe[0]);
        dup2(input_pipe[0], STDIN_FILENO);
        dup2(output_pipe[1], STDOUT_FILENO);
        //dup2(output_pipe[1], STDERR_FILENO); TODO: Need to implement error catching method as next
        execlp("python3", "python3", "-i" ,NULL);
        exit(1); 
    } else { // Parent process
        close(input_pipe[0]);
        close(output_pipe[1]);

        python_subprocess_t *subprocess = apr_pcalloc(r->pool, sizeof(python_subprocess_t));
        subprocess->input = fdopen(input_pipe[1], "w");
        subprocess->output = fdopen(output_pipe[0], "r");
        subprocess->pid = pid;

        return subprocess;
    }
}

static char* replace_pattern(const char *input, apr_table_t *GET, apr_array_header_t *POST, apr_pool_t *pool) {
    const char *pattern_start_get = "~DP_GET['";
    const char *pattern_start_post = "~DP_POST['";
    const char *pattern_end = "']";
    const char *start_pos, *end_pos;
    const char *key, *value;
    char *result, *modifiable_input, *current_pos;
    size_t result_len;

    // Copy the input to a modifiable string
    modifiable_input = apr_pstrdup(pool, input);
    current_pos = modifiable_input;

    while ((start_pos = strstr(current_pos, pattern_start_get)) != NULL || (start_pos = strstr(current_pos, pattern_start_post)) != NULL) {
        // Determine whether it's DP_GET or DP_POST
        int is_get = (start_pos == strstr(current_pos, pattern_start_get));
        start_pos += (is_get ? strlen(pattern_start_get) : strlen(pattern_start_post));

        // Find the end of the pattern
        end_pos = strstr(start_pos, pattern_end);
        if (!end_pos) {
            break;
        }

        // Extract the key
        size_t key_len = end_pos - start_pos;
        key = apr_pstrndup(pool, start_pos, key_len);

        // Retrieve the value from the appropriate table (GET or POST)
        if (is_get) {
            value = (const char *)apr_table_get(GET, key);
        } else {
            // Search through the POST array to find matching key
            value = NULL;
            int i;
            for (i = 0; i < POST->nelts; ++i) {
                apr_table_entry_t *entry = &APR_ARRAY_IDX(POST, i, apr_table_entry_t);
                if (strcmp(entry->key, key) == 0) {
                    value = entry->val;
                    break;
                }
            }
        }

        if (!value) {
            value = ""; // Default value if key not found
        }

        result_len = strlen(modifiable_input) - (end_pos - current_pos) + strlen(value);
        result = apr_pcalloc(pool, result_len + 1);

        size_t prefix_len = start_pos - modifiable_input - (is_get ? strlen(pattern_start_get) : strlen(pattern_start_post));
        strncpy(result, modifiable_input, prefix_len);
        result[prefix_len] = '\0';
        strcat(result, value);
        strcat(result, end_pos + strlen(pattern_end));

        current_pos = result;
        modifiable_input = result;
    }

    return modifiable_input;
}

/**
 * Fetches both GET and POST params and replaces with Python code
*/
static char* read_and_process_pattern(const char *filename, request_rec *r, apr_table_t *GET, apr_array_header_t *POST) {
    apr_file_t *file;
    apr_status_t rv;
    char buffer[128];
    apr_size_t bytes_read;
    apr_pool_t *pool = r->pool;
    char *file_content = NULL;

    rv = apr_file_open(&file, filename, APR_FOPEN_READ, APR_OS_DEFAULT, pool);
    if (rv != APR_SUCCESS) {
        //ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Error opening file: %s", filename);
        return NULL;
    }

    while ((rv = apr_file_gets(buffer, sizeof(buffer), file)) == APR_SUCCESS) {
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        }

        char *processed_line = replace_pattern(buffer, GET, POST, pool);
        file_content = apr_pstrcat(pool, file_content ? file_content : "", processed_line, "\n", NULL);
    }

    apr_file_close(file);
    return file_content;
}

void read_and_process_file(const char *buffer, request_rec *r) {
    char *output_buffer = apr_pcalloc(r->pool, 134217728); 
    char *result_buffer = apr_pcalloc(r->pool, 134217728);
    char *current_position = buffer;

    python_subprocess_t *subprocess = start_python_subprocess(r);
    if (!subprocess) {
        ap_rprintf(r, "Failed to start Python subprocess\n");
        return;
    }

    // Parse the content
    while (1) {
        char *start = strstr(current_position, "<?dp");
        if (!start) {
            strcat(result_buffer, current_position); 
            break;
        }
        strncat(result_buffer, current_position, start - current_position);

        start += 4; // Move past "<?dp"
        char *end = strstr(start, "?>");
        if (end) {
            *end = '\0';

            execute_python_code(subprocess, start, output_buffer, 134217728, r);
            strcat(result_buffer, output_buffer); 

            current_position = end + 2; // Move past "?>"
        } else {
            break; // No closing tag found
        }
    }

    ap_rprintf(r, "%s", result_buffer);

    // Clean up the subprocess
    fclose(subprocess->input);
    fclose(subprocess->output);
    waitpid(subprocess->pid, NULL, 0);
}

static int directpython_handler(request_rec *r)
{
    int rc, exists;
    apr_finfo_t finfo;
    apr_file_t *file;
    char *filename;
    apr_table_t *GET;
    apr_array_header_t *POST;

    if (strcmp(r->handler, "directpython")) {
        return DECLINED;
    }

    filename = apr_pstrdup(r->pool, r->filename);
    
    rc = apr_stat(&finfo, filename, APR_FINFO_MIN, r->pool);
    if (rc == APR_SUCCESS) {
        exists =
        (
            (finfo.filetype != APR_NOFILE)
        &&  !(finfo.filetype & APR_DIR)
        );
        if (!exists) return HTTP_NOT_FOUND;
    }
    else return HTTP_FORBIDDEN;
    
    apr_initialize();
    ap_args_to_table(r, &GET);
    ap_parse_form_data(r, NULL, &POST, -1, 8192);
    
    ap_set_content_type(r, "text/html");

    char *processed_content = read_and_process_pattern(filename, r, GET, POST);
    if (!processed_content) {
        ap_rputs("Error processing params", r);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    // Further process the content
    read_and_process_file(processed_content, r);

    return OK;
}

static void directpython_register_hooks(apr_pool_t *p)
{
    printf("\n ** directpython_register_hooks  **\n\n");
    ap_hook_handler(directpython_handler, NULL, NULL, APR_HOOK_LAST);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA directpython_module = {
    STANDARD20_MODULE_STUFF, 
    NULL, /* create per-dir    config structures */
    NULL, /* merge  per-dir    config structures */
    NULL, /* create per-server config structures */
    NULL, /* merge  per-server config structures */
    NULL, /* table of config file commands       */
    directpython_register_hooks  /* register hooks */
};


void execute_python_code(python_subprocess_t *subprocess, const char *code, char *output, size_t output_size, request_rec *r) {
    if (subprocess && subprocess->input && subprocess->output) {
        fprintf(subprocess->input, "%s\nprint('<<<END OF OUTPUT>>>')\n", code);
        fflush(subprocess->input);

        size_t total_length = 0;
        char buffer[128];
        int end_marker_found = 0;

        while (fgets(buffer, sizeof(buffer), subprocess->output) != NULL) {
            buffer[sizeof(buffer) - 1] = '\0';

            if (strstr(buffer, "<<<END OF OUTPUT>>>") != NULL) {
                end_marker_found = 1;
                break;
            }
            size_t length = strlen(buffer);
            if (total_length + length < output_size - 1) {
                strcpy(output + total_length, buffer);
                total_length += length;
            } else {
                strncpy(output + total_length, buffer, output_size - total_length - 1);
                total_length = output_size - 1;
                break;
            }
        }

        if (!end_marker_found) {
            // Todo: ERROR catching method
        }

        if (total_length == 0) {
            strncpy(output, code, output_size);
        } else {
            output[total_length] = '\0'; // Null-terminate the output string
        }
    } else {
        strncpy(output, "Error executing script", output_size);
    }
}

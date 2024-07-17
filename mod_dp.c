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
        //dup2(output_pipe[1], STDERR_FILENO); TODO: Need to implement error caching method as next
        execlp("python3", "python3", "-i", NULL);
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
static int directpython_handler(request_rec *r)
{
    int rc, exists;
    apr_finfo_t finfo;
    apr_file_t *file;
    char *filename;
    char buffer[256];
    apr_size_t readBytes;
    int n;
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

    
    read_and_process_file(filename, r);

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
            // Todo: ERROR caching method
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

void read_and_process_file(const char *filename, request_rec *r) {
    apr_file_t *file;
    apr_status_t rc;

    rc = apr_file_open(&file, filename, APR_READ, APR_OS_DEFAULT, r->pool);
    if (rc == APR_SUCCESS) {
        apr_off_t offset = 0;
        apr_file_seek(file, APR_END, &offset);
        apr_size_t size = (apr_size_t)offset;
        char *buffer = apr_pcalloc(r->pool, size + 1);

        offset = 0;
        apr_file_seek(file, APR_SET, &offset);

        int status = apr_file_read(file, buffer, &size);
        if (status != APR_SUCCESS) {
            ap_rprintf(r, "Could not read file\n");
        } else {
            buffer[size] = '\0'; 

            char *output_buffer = apr_pcalloc(r->pool, 1024); 
            char *result_buffer = apr_pcalloc(r->pool, size + 1);
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

                    execute_python_code(subprocess, start, output_buffer, 1024, r);
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
        apr_file_close(file);
    } else {
        ap_rprintf(r, "Could not open file\n");
    }
}
/*
 *crun - OCI runtime written in C
 *
 *Copyright (C) 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
 *crun is free software; you can redistribute it and/or modify
 *it under the terms of the GNU Lesser General Public License as published by
 *the Free Software Foundation; either version 2.1 of the License, or
 *(at your option) any later version.
 *
 *crun is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 *MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *GNU Lesser General Public License for more details.
 *
 *You should have received a copy of the GNU Lesser General Public License
 *along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
  An example of using this module:

import python_crun
import json

spec = json.loads(python_crun.spec())
spec['root']['path'] = '/path/to/the/rootfs'
spec['process']['args'] = ['/bin/echo', 'hello from a container']

ctr = python_crun.load_from_memory(json.dumps(spec))
ctx = python_crun.make_context("test-container")
python_crun.set_verbosity(python_crun.VERBOSITY_ERROR)
python_crun.run(ctx, ctr)
*/

#include <config.h>
#include <Python.h>
#include <libcrun/container.h>
#include <libcrun/status.h>
#include <libcrun/utils.h>
#include <libcrun/error.h>

#define CONTEXT_OBJ_TAG "crun-context"
#define CONTAINER_OBJ_TAG "crun-container"

static PyObject *
set_error (libcrun_error_t *err)
{
  if ((*err)->status == 0)
    PyErr_SetString (PyExc_RuntimeError, (*err)->msg);
  else
    {
      cleanup_free char *msg = NULL;
      int ret;

      ret = asprintf (&msg, "%s: %s", (*err)->msg, strerror ((*err)->status));
      if (LIKELY (ret >= 0))
        PyErr_SetString (PyExc_RuntimeError, msg);
      else
        msg = NULL;
    }

  libcrun_error_release (err);
  return NULL;
}

static void
free_container (PyObject *ptr)
{
  libcrun_container_t *ctr = PyCapsule_GetPointer (ptr, CONTAINER_OBJ_TAG);
  free_runtime_spec_schema_config_schema (ctr->container_def);
}

static PyObject *
container_load_from_file (PyObject *self arg_unused, PyObject *args)
{
  libcrun_error_t err;
  const char *path;
  libcrun_container_t *ctr;

  if (!PyArg_ParseTuple (args, "s", &path))
    return NULL;

  ctr = libcrun_container_load_from_file (path, &err);
  if (ctr == NULL)
    return set_error (&err);

  return PyCapsule_New (ctr, CONTAINER_OBJ_TAG, free_container);
}

static PyObject *
container_load_from_memory (PyObject *self arg_unused, PyObject *args)
{
  libcrun_error_t err;
  const char *def;
  libcrun_container_t *ctr;

  if (!PyArg_ParseTuple (args, "s", &def))
    return NULL;

  ctr = libcrun_container_load_from_memory (def, &err);
  if (ctr == NULL)
    return set_error (&err);

  return PyCapsule_New (ctr, CONTAINER_OBJ_TAG, free_container);
}

static void
free_context (void *ptr)
{
  libcrun_context_t *ctx = ptr;
  char *id = (char *) ctx->id;
  free (ctx->state_root);
  free (ctx->notify_socket);
  free (id);
  free (ctx);
}

static PyObject *
make_context (PyObject *self arg_unused, PyObject *args, PyObject *kwargs)
{
  char *id = NULL;
  char *bundle = NULL;
  char *state_root = NULL;
  char *notify_socket = NULL;
  static char *kwlist[] =
    { "id", "bundle", "state_root", "systemd_cgroup", "notify_socket", "detach", "no_new_keyring", "force_no_cgroup", "no_pivot", NULL };
  libcrun_context_t *ctx = malloc (sizeof (*ctx));
  if (ctx == NULL)
    return NULL;

  memset (ctx, 0, sizeof (*ctx));
  ctx->fifo_exec_wait_fd = -1;

  if (!PyArg_ParseTupleAndKeywords
      (args, kwargs, "s|ssbsbbbb", kwlist, &id, &bundle, &state_root,
       &ctx->systemd_cgroup, &notify_socket, &ctx->detach, &ctx->no_new_keyring, &ctx->force_no_cgroup, &ctx->no_pivot))
    return NULL;

  ctx->id = xstrdup (id);
  ctx->bundle = xstrdup (bundle ? bundle : ".");
  ctx->state_root = xstrdup (state_root);
  ctx->notify_socket = xstrdup (notify_socket);
  return PyCapsule_New (ctx, CONTEXT_OBJ_TAG, NULL);
}

static PyObject *
container_run (PyObject *self arg_unused, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  PyObject *ctr_obj = NULL;
  libcrun_container_t *ctr;
  libcrun_context_t *ctx;
  int ret;

  if (!PyArg_ParseTuple (args, "OO", &ctx_obj, &ctr_obj))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  ctr = PyCapsule_GetPointer (ctr_obj, CONTAINER_OBJ_TAG);
  if (ctr == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS;
  ret = libcrun_container_run (ctx, ctr, 0, &err);
  Py_END_ALLOW_THREADS;
  if (ret < 0)
    return set_error (&err);

  return PyLong_FromLong (ret);
}

static PyObject *
container_create (PyObject *self arg_unused, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  PyObject *ctr_obj = NULL;
  libcrun_container_t *ctr;
  libcrun_context_t *ctx;
  int ret;

  if (!PyArg_ParseTuple (args, "OO", &ctx_obj, &ctr_obj))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  ctr = PyCapsule_GetPointer (ctr_obj, CONTAINER_OBJ_TAG);
  if (ctr == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS;
  ret = libcrun_container_create (ctx, ctr, LIBCRUN_CREATE_OPTIONS_PREFORK, &err);
  Py_END_ALLOW_THREADS;
  if (ret < 0)
    return set_error (&err);

  return PyLong_FromLong (ret);
}

static PyObject *
container_delete (PyObject *self arg_unused, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  char *id = NULL;
  bool force;
  libcrun_context_t *ctx;
  int ret;

  if (!PyArg_ParseTuple (args, "Osb", &ctx_obj, &id, &force))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS;
  ret = libcrun_container_delete (ctx, NULL, id, force, &err);
  Py_END_ALLOW_THREADS;
  if (ret < 0)
    return set_error (&err);

  Py_RETURN_NONE;
}

static PyObject *
container_kill (PyObject *self arg_unused, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  char *id = NULL;
  char *signal;
  libcrun_context_t *ctx;
  int ret;

  if (!PyArg_ParseTuple (args, "Oss", &ctx_obj, &id, &signal))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS;
  ret = libcrun_container_kill (ctx, id, signal, &err);
  Py_END_ALLOW_THREADS;
  if (ret < 0)
    return set_error (&err);

  Py_RETURN_NONE;
}

static PyObject *
container_start (PyObject *self arg_unused, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  char *id = NULL;
  libcrun_context_t *ctx;
  int ret;

  if (!PyArg_ParseTuple (args, "Os", &ctx_obj, &id))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS;
  ret = libcrun_container_start (ctx, id, &err);
  Py_END_ALLOW_THREADS;
  if (ret < 0)
    return set_error (&err);

  return PyLong_FromLong (ret);
}

static PyObject *
containers_list (PyObject *self arg_unused, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  libcrun_context_t *ctx;
  libcrun_container_list_t *containers, *it;
  PyObject *retobj;
  Py_ssize_t i = 0;
  int ret;

  if (!PyArg_ParseTuple (args, "O", &ctx_obj))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS;
  ret = libcrun_get_containers_list (&containers, ctx->state_root, &err);
  Py_END_ALLOW_THREADS;
  if (ret < 0)
    return set_error (&err);

  i = 0;
  for (it = containers; it; it = it->next)
    i++;

  retobj = PyList_New (i);
  if (retobj == NULL)
    return NULL;

  i = 0;
  for (it = containers; it; it = it->next)
    PyList_SetItem (retobj, i++, PyUnicode_FromString (it->name));

  libcrun_free_containers_list (containers);

  return retobj;
}

static PyObject *
container_status (PyObject *self arg_unused, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  libcrun_context_t *ctx;
  char *id = NULL;
  libcrun_container_status_t status;
  cleanup_free char *buffer = NULL;
  FILE *memfile;
  int ret;

  if (!PyArg_ParseTuple (args, "Os", &ctx_obj, &id))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  buffer = malloc (4096);
  if (buffer == NULL)
    return NULL;

  /* A bit silly (and expensive), libcrun_container_state needs a refactoring
     to make this nicer. */
  memset (buffer, 0, 4096);

  memfile = fmemopen (buffer, 4095, "w");
  Py_BEGIN_ALLOW_THREADS;
  ret = libcrun_container_state (ctx, id, memfile, &err);
  Py_END_ALLOW_THREADS;
  if (ret < 0)
    return set_error (&err);

  fclose (memfile);

  return PyUnicode_FromString (buffer);
}

static int
load_json_file (yajl_val *out, const char *jsondata, struct parser_context *ctx arg_unused, libcrun_error_t *err)
{
    char errbuf[1024];

    *err = NULL;

    *out = yajl_tree_parse (jsondata, errbuf, sizeof (errbuf));
    if (*out == NULL)
      return libcrun_make_error (err, 0, "cannot parse the data: `%s`", errbuf);

    return 0;
}

static PyObject *
container_update (PyObject *self arg_unused, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  libcrun_context_t *ctx;
  char *id = NULL;
  char *content = NULL;
  yajl_val tree = NULL;
  int ret;
  parser_error parser_err = NULL;
  struct parser_context parser_ctx = { 0, stderr };
  runtime_spec_schema_config_schema_process *process = NULL;

  if (!PyArg_ParseTuple (args, "Oss", &ctx_obj, &id, &content))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  ret = load_json_file (&tree, content, &parser_ctx, &err);
  if (UNLIKELY (ret < 0))
    return set_error (&err);

  process = make_runtime_spec_schema_config_schema_process (tree, &parser_ctx, &parser_err);
  yajl_tree_free (tree);
  if (process == NULL)
    {
      cleanup_free char *msg = NULL;
      ret = asprintf (&msg, "cannot parse process: %s", parser_err);
      if (LIKELY (ret >= 0))
        PyErr_SetString (PyExc_RuntimeError, msg);
      else
        msg = NULL;
      free (parser_err);
      return NULL;
    }

  Py_BEGIN_ALLOW_THREADS;
  ret = libcrun_container_exec (ctx, id, process, &err);
  Py_END_ALLOW_THREADS;

  free_runtime_spec_schema_config_schema_process (process);
  if (ret < 0)
    return set_error (&err);
  Py_RETURN_NONE;
}

static PyObject *
container_spec (PyObject *self arg_unused, PyObject *args arg_unused)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  libcrun_context_t *ctx;
  char *id = NULL;
  libcrun_container_status_t status;
  cleanup_free char *buffer = NULL;
  FILE *memfile;
  int ret;

  buffer = malloc (4096);
  if (buffer == NULL)
    return NULL;

  memfile = fmemopen (buffer, 4095, "w");
  Py_BEGIN_ALLOW_THREADS;
  ret = libcrun_container_spec (geteuid () == 0, memfile, &err);
  Py_END_ALLOW_THREADS;
  if (ret < 0)
    return set_error (&err);
  buffer[ret] = '\0';
  fclose (memfile);

  return PyUnicode_FromString (buffer);
}

static PyObject *
get_verbosity (PyObject *self arg_unused, PyObject *args)
{
  return PyLong_FromLong (libcrun_get_verbosity());
}

static PyObject *
set_verbosity (PyObject *self arg_unused, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  libcrun_context_t *ctx;
  int verbosity;

  if (!PyArg_ParseTuple (args, "i", &verbosity))
    return NULL;

  libcrun_set_verbosity (verbosity);
  Py_RETURN_NONE;
}

static PyMethodDef CrunMethods[] = {
  {"load_from_file", container_load_from_file, METH_VARARGS,
   "Load an OCI container from file."},
  {"load_from_memory", container_load_from_memory, METH_VARARGS,
   "Load an OCI container from memory."},
  {"run", container_run, METH_VARARGS, "Run a container."},
  {"create", container_create, METH_VARARGS, "Create a container."},
  {"delete", container_delete, METH_VARARGS, "Delete a container."},
  {"kill", container_kill, METH_VARARGS, "Kill a container."},
  {"list", containers_list, METH_VARARGS, "List the containers."},
  {"status", container_status, METH_VARARGS,
   "Get the status of a container."},
  {"update", container_update, METH_VARARGS,
   "Update the constraints of a container."},
  {"spec", container_spec, METH_VARARGS,
   "Generate a new configuration file."},
  {"make_context", (PyCFunction) make_context, METH_VARARGS | METH_KEYWORDS,
   "Create a context object."},
  {"set_verbosity", set_verbosity, METH_VARARGS, "Set the logging verbosity."},
  {"get_verbosity", get_verbosity, METH_NOARGS, "Get the logging verbosity."},
  {"spec", container_spec, METH_VARARGS,
   "Generate a new configuration file."},
  {NULL, NULL, 0, NULL}
};

struct PyModuleDef crun_mod =
  {
   PyModuleDef_HEAD_INIT,
   "python_crun",
   NULL,
   0,
   CrunMethods,
  };

PyMODINIT_FUNC
PyInit_python_crun (void)
{
  PyObject *ret;
  ret = PyModule_Create (&crun_mod);
  if (ret == NULL)
    return ret;
  (void) PyModule_AddIntConstant (ret, "VERBOSITY_ERROR", LIBCRUN_VERBOSITY_ERROR);
  (void) PyModule_AddIntConstant (ret, "VERBOSITY_WARNING", LIBCRUN_VERBOSITY_WARNING);
  (void) PyModule_AddIntConstant (ret, "VERBOSITY_DEBUG", LIBCRUN_VERBOSITY_DEBUG);
  return ret;
}

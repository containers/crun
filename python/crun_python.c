/*
 *crun - OCI runtime written in C
 *
 *Copyright (C) 2018 Giuseppe Scrivano <giuseppe@scrivano.org>
 *crun is free software; you can redistribute it and/or modify
 *it under the terms of the GNU Lesser General Public License as published by
 *the Free Software Foundation; either version 3 of the License, or
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
      asprintf (&msg, "%s: %s", (*err)->msg, strerror ((*err)->status));
      if (msg == NULL)
	return NULL;
      PyErr_SetString (PyExc_RuntimeError, msg);
    }

  crun_error_release (err);
  return NULL;
}

static void
free_container (PyObject *ptr)
{
  libcrun_container *ctr = PyCapsule_GetPointer (ptr, CONTAINER_OBJ_TAG);
  free_oci_container (ctr->container_def);
}

static PyObject *
container_load_from_file (PyObject *self, PyObject *args)
{
  libcrun_error_t err;
  const char *path;
  libcrun_container *ctr;

  if (!PyArg_ParseTuple (args, "s", &path))
    return NULL;

  ctr = libcrun_container_load_from_file (path, &err);
  if (ctr == NULL)
    return set_error (&err);

  return PyCapsule_New (ctr, CONTAINER_OBJ_TAG, free_container);
}

static PyObject *
container_load_from_memory (PyObject *self, PyObject *args)
{
  libcrun_error_t err;
  const char *def;
  libcrun_container *ctr;

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
  struct libcrun_context_s *ctx = ptr;
  char *id = (char *) ctx->id;
  free (ctx->state_root);
  free (ctx->notify_socket);
  free (id);
  free (ctx);
}

static PyObject *
make_context (PyObject *self, PyObject *args, PyObject *kwargs)
{
  char *id = NULL;
  char *bundle = NULL;
  char *state_root = NULL;
  char *notify_socket = NULL;
  static char *kwlist[] =
    { "id", "state-root", "systemd-cgroup", "notify-socket", NULL };
  struct libcrun_context_s *ctx = malloc (sizeof (*ctx));
  if (ctx == NULL)
    return NULL;

  memset (ctx, 0, sizeof (*ctx));
  ctx->stderr = stderr;
  ctx->fifo_exec_wait_fd = -1;

  if (!PyArg_ParseTupleAndKeywords
      (args, kwargs, "s|sssbs", kwlist, &id, &bundle, &state_root,
       &ctx->systemd_cgroup, &notify_socket))
    return NULL;

  ctx->id = xstrdup (id);
  ctx->bundle = xstrdup (bundle ? bundle : ".");
  ctx->state_root = xstrdup (state_root);
  ctx->notify_socket = xstrdup (notify_socket);
  return PyCapsule_New (ctx, CONTEXT_OBJ_TAG, NULL);

}

static PyObject *
container_run (PyObject *self, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  PyObject *ctr_obj = NULL;
  libcrun_container *ctr;
  struct libcrun_context_s *ctx;

  if (!PyArg_ParseTuple (args, "OO", &ctx_obj, &ctr_obj))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  ctr = PyCapsule_GetPointer (ctr_obj, CONTAINER_OBJ_TAG);
  if (ctr == NULL)
    return NULL;

  if (libcrun_container_run (ctx, ctr, 0, &err) < 0)
    return set_error (&err);

  Py_RETURN_NONE;
}

static PyObject *
container_create (PyObject *self, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  PyObject *ctr_obj = NULL;
  libcrun_container *ctr;
  struct libcrun_context_s *ctx;

  if (!PyArg_ParseTuple (args, "OO", &ctx_obj, &ctr_obj))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  ctr = PyCapsule_GetPointer (ctr_obj, CONTAINER_OBJ_TAG);
  if (ctr == NULL)
    return NULL;

  if (libcrun_container_create (ctx, ctr, &err) < 0)
    return set_error (&err);

  Py_RETURN_NONE;
}

static PyObject *
container_delete (PyObject *self, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  char *id = NULL;
  bool force;
  struct libcrun_context_s *ctx;

  if (!PyArg_ParseTuple (args, "Osn", &ctx_obj, &id, &force))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  if (libcrun_container_delete (ctx, NULL, id, force, &err) < 0)
    return set_error (&err);

  Py_RETURN_NONE;
}

static PyObject *
container_kill (PyObject *self, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  char *id = NULL;
  int signal;
  struct libcrun_context_s *ctx;

  if (!PyArg_ParseTuple (args, "Osi", &ctx_obj, &id, &signal))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  if (libcrun_container_kill (ctx, id, signal, &err) < 0)
    return set_error (&err);

  Py_RETURN_NONE;
}

static PyObject *
container_start (PyObject *self, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  char *id = NULL;
  struct libcrun_context_s *ctx;

  if (!PyArg_ParseTuple (args, "Os", &ctx_obj, &id))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  if (libcrun_container_start (ctx, id, &err) < 0)
    return set_error (&err);

  Py_RETURN_NONE;
}

static PyObject *
containers_list (PyObject *self, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  struct libcrun_context_s *ctx;
  libcrun_container_list_t *containers, *it;
  PyObject *ret;
  Py_ssize_t i = 0;

  if (!PyArg_ParseTuple (args, "O", &ctx_obj))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  if (libcrun_get_containers_list (&containers, ctx->state_root, &err) < 0)
    return set_error (&err);

  i = 0;
  for (it = containers; it; it = it->next)
    i++;
  ret = PyList_New (i);
  if (ret == NULL)
    return NULL;

  i = 0;
  for (it = containers; it; it = it->next)
    PyList_SetItem (ret, i++, PyUnicode_FromString (it->name));

  libcrun_free_containers_list (containers);

  return ret;
}

static PyObject *
container_status (PyObject *self, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  struct libcrun_context_s *ctx;
  char *id = NULL;
  libcrun_container_status_t status;
  cleanup_free char *buffer = NULL;
  FILE *memfile;

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
  if (libcrun_container_state (ctx, id, memfile, &err) < 0)
    return set_error (&err);
  fclose (memfile);

  return PyUnicode_FromString (buffer);
}

static PyObject *
container_update (PyObject *self, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  struct libcrun_context_s *ctx;
  char *id = NULL;
  char *content = NULL;
  yajl_val tree = NULL;
  int ret;
  parser_error parser_err = NULL;
  struct parser_context parser_ctx = { 0, NULL };
  oci_container_process *process = NULL;

  if (!PyArg_ParseTuple (args, "Oss", &ctx_obj, &id, &content))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  ret = parse_json_file (&tree, content, &parser_ctx, &err);
  if (UNLIKELY (ret < 0))
    return set_error (&err);

  process = make_oci_container_process (tree, &parser_ctx, &parser_err);
  yajl_tree_free (tree);
  if (process == NULL)
    {
      cleanup_free char *msg = NULL;
      asprintf (&msg, "cannot parse process: %s", parser_err);
      if (msg == NULL)
	return NULL;
      free (parser_err);
      PyErr_SetString (PyExc_RuntimeError, msg);
      return NULL;
    }

  ret = libcrun_container_exec (ctx, id, process, &err);
  free_oci_container_process (process);
  if (ret < 0)
    return set_error (&err);
  Py_RETURN_NONE;
}

static PyObject *
container_spec (PyObject *self, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  struct libcrun_context_s *ctx;
  char *id = NULL;
  libcrun_container_status_t status;
  cleanup_free char *buffer = NULL;
  FILE *memfile;
  int ret;

  buffer = malloc (4096);
  if (buffer == NULL)
    return NULL;

  memfile = fmemopen (buffer, 4095, "w");
  ret = libcrun_container_spec (geteuid () == 0, memfile, &err);
  if (ret < 0)
    return set_error (&err);
  buffer[ret] = '\0';
  fclose (memfile);

  return PyUnicode_FromString (buffer);
}

static PyObject *
get_verbosity (PyObject *self, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  struct libcrun_context_s *ctx;
  int verbosity;

  if (!PyArg_ParseTuple (args, "i", &verbosity))
    return NULL;

  return PyLong_FromLong (libcrun_get_verbosity (verbosity));
}

static PyObject *
set_verbosity (PyObject *self, PyObject *args)
{
  libcrun_error_t err;
  PyObject *ctx_obj = NULL;
  struct libcrun_context_s *ctx;
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
  {"create", container_run, METH_VARARGS, "Create a container."},
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
  {"get_verbosity", get_verbosity, METH_VARARGS, "Get the logging verbosity."},
  {"spec", container_spec, METH_VARARGS,
   "Generate a new configuration file."},
  {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initpython_crun (void)
{
  PyObject *module = Py_InitModule ("python_crun", CrunMethods);
  (void) PyModule_AddIntConstant (module, "VERBOSITY_ERROR", LIBCRUN_VERBOSITY_ERROR);
  (void) PyModule_AddIntConstant (module, "VERBOSITY_WARNING", LIBCRUN_VERBOSITY_WARNING);
}

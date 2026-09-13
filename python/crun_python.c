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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libcrun/libcrun.h>

#define arg_unused __attribute__ ((unused))

#define CONTEXT_OBJ_TAG "crun-context"
#define CONTAINER_OBJ_TAG "crun-container"

static PyObject *
set_error (libcrun_error_t *err)
{
  int status = libcrun_error_get_status (*err);
  const char *msg = libcrun_error_get_message (*err);

  if (status == 0)
    PyErr_SetString (PyExc_RuntimeError, msg);
  else
    {
      char *full = NULL;
      int ret;

      ret = asprintf (&full, "%s: %s", msg, strerror (status));
      if (ret >= 0)
        {
          PyErr_SetString (PyExc_RuntimeError, full);
          free (full);
        }
    }

  libcrun_error_release (err);
  return NULL;
}

static void
free_container (PyObject *ptr)
{
  libcrun_container_t *ctr = PyCapsule_GetPointer (ptr, CONTAINER_OBJ_TAG);
  libcrun_container_free (ctr);
}

static PyObject *
container_load_from_file (PyObject *self arg_unused, PyObject *args)
{
  libcrun_error_t err = NULL;
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
  libcrun_error_t err = NULL;
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
free_context (PyObject *ptr)
{
  libcrun_context_t *ctx = PyCapsule_GetPointer (ptr, CONTEXT_OBJ_TAG);

  libcrun_context_free (ctx);
}

static PyObject *
make_context (PyObject *self arg_unused, PyObject *args, PyObject *kwargs)
{
  char *id = NULL;
  char *bundle = NULL;
  char *state_root = NULL;
  char *notify_socket = NULL;
  unsigned char systemd_cgroup = 0;
  unsigned char detach = 0;
  unsigned char no_new_keyring = 0;
  unsigned char force_no_cgroup = 0;
  unsigned char no_pivot = 0;
  static char *kwlist[] =
    { "id", "bundle", "state_root", "systemd_cgroup", "notify_socket", "detach", "no_new_keyring", "force_no_cgroup", "no_pivot", NULL };
  libcrun_error_t err = NULL;
  libcrun_context_t *ctx;

  if (!PyArg_ParseTupleAndKeywords
      (args, kwargs, "s|ssbsbbbb", kwlist, &id, &bundle, &state_root,
       &systemd_cgroup, &notify_socket, &detach, &no_new_keyring, &force_no_cgroup, &no_pivot))
    return NULL;

  ctx = libcrun_context_new (id, state_root, &err);
  if (ctx == NULL)
    return set_error (&err);

  libcrun_context_set_bundle (ctx, bundle ? bundle : ".");
  if (notify_socket)
    libcrun_context_set_notify_socket (ctx, notify_socket);
  libcrun_context_set_systemd_cgroup (ctx, systemd_cgroup);
  libcrun_context_set_detach (ctx, detach);
  libcrun_context_set_no_new_keyring (ctx, no_new_keyring);
  libcrun_context_set_force_no_cgroup (ctx, force_no_cgroup);
  libcrun_context_set_no_pivot (ctx, no_pivot);

  return PyCapsule_New (ctx, CONTEXT_OBJ_TAG, free_context);
}

static PyObject *
container_run (PyObject *self arg_unused, PyObject *args)
{
  libcrun_error_t err = NULL;
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
  libcrun_error_t err = NULL;
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
  libcrun_error_t err = NULL;
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
  ret = libcrun_container_delete (ctx, id, force, &err);
  Py_END_ALLOW_THREADS;
  if (ret < 0)
    return set_error (&err);

  Py_RETURN_NONE;
}

static PyObject *
container_kill (PyObject *self arg_unused, PyObject *args)
{
  libcrun_error_t err = NULL;
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
  libcrun_error_t err = NULL;
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
  libcrun_error_t err = NULL;
  PyObject *ctx_obj = NULL;
  libcrun_context_t *ctx;
  libcrun_container_list_t *containers = NULL;
  libcrun_container_iter_t *it;
  const char *id;
  PyObject *retobj;
  Py_ssize_t i = 0;
  int ret;

  if (!PyArg_ParseTuple (args, "O", &ctx_obj))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS;
  ret = libcrun_container_list (ctx, &containers, &err);
  Py_END_ALLOW_THREADS;
  if (ret < 0)
    return set_error (&err);

  i = 0;
  it = libcrun_container_list_iter (containers);
  while (libcrun_container_iter_next (it, NULL))
    i++;
  libcrun_container_iter_free (it);

  retobj = PyList_New (i);
  if (retobj == NULL)
    {
      libcrun_container_list_free (containers);
      return NULL;
    }

  i = 0;
  it = libcrun_container_list_iter (containers);
  while (libcrun_container_iter_next (it, &id))
    PyList_SetItem (retobj, i++, PyUnicode_FromString (id));
  libcrun_container_iter_free (it);

  libcrun_container_list_free (containers);

  return retobj;
}

static PyObject *
container_status (PyObject *self arg_unused, PyObject *args)
{
  libcrun_error_t err = NULL;
  PyObject *ctx_obj = NULL;
  libcrun_context_t *ctx;
  char *id = NULL;
  char *buffer = NULL;
  PyObject *retobj;
  int ret;

  if (!PyArg_ParseTuple (args, "Os", &ctx_obj, &id))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS;
  ret = libcrun_container_state_json (ctx, id, &buffer, &err);
  Py_END_ALLOW_THREADS;
  if (ret < 0)
    return set_error (&err);

  retobj = PyUnicode_FromString (buffer);
  free (buffer);

  return retobj;
}

static PyObject *
container_update (PyObject *self arg_unused, PyObject *args)
{
  libcrun_error_t err = NULL;
  PyObject *ctx_obj = NULL;
  libcrun_context_t *ctx;
  char *id = NULL;
  char *content = NULL;
  int ret;

  if (!PyArg_ParseTuple (args, "Oss", &ctx_obj, &id, &content))
    return NULL;

  ctx = PyCapsule_GetPointer (ctx_obj, CONTEXT_OBJ_TAG);
  if (ctx == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS;
  ret = libcrun_container_exec_json (ctx, id, content, &err);
  Py_END_ALLOW_THREADS;
  if (ret < 0)
    return set_error (&err);

  Py_RETURN_NONE;
}

static PyObject *
container_spec (PyObject *self arg_unused, PyObject *args arg_unused)
{
  libcrun_error_t err = NULL;
  char *buffer = NULL;
  PyObject *retobj;
  int ret;

  ret = libcrun_container_spec_json (geteuid () == 0, &buffer, &err);
  if (ret < 0)
    return set_error (&err);

  retobj = PyUnicode_FromString (buffer);
  free (buffer);

  return retobj;
}

static PyObject *
get_verbosity (PyObject *self arg_unused, PyObject *args arg_unused)
{
  return PyLong_FromLong (libcrun_get_verbosity ());
}

static PyObject *
set_verbosity (PyObject *self arg_unused, PyObject *args)
{
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
  {"start", container_start, METH_VARARGS, "Start a container."},
  {"list", containers_list, METH_VARARGS, "List the containers."},
  {"status", container_status, METH_VARARGS,
   "Get the status of a container."},
  {"update", container_update, METH_VARARGS,
   "Update the constraints of a container."},
  {"spec", container_spec, METH_VARARGS,
   "Generate a new configuration file."},
  {"make_context", (PyCFunction) (void (*) (void)) make_context, METH_VARARGS | METH_KEYWORDS,
   "Create a context object."},
  {"set_verbosity", set_verbosity, METH_VARARGS, "Set the logging verbosity."},
  {"get_verbosity", get_verbosity, METH_NOARGS, "Get the logging verbosity."},
  {NULL, NULL, 0, NULL}
};

struct PyModuleDef crun_mod =
  {
   PyModuleDef_HEAD_INIT,
   "python_crun",
   NULL,
   0,
   CrunMethods,
   NULL,
   NULL,
   NULL,
   NULL,
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

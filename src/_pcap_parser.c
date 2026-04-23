#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <pcap.h>
#include "packet_parser_core.h"

struct packet_handler_context {
    PyObject *result;
    int failed;
};

static double packet_timestamp(const struct pcap_pkthdr *header) {
    return (double)header->ts.tv_sec + (double)header->ts.tv_usec / 1e6;
}

static PyObject *build_packet_tuple(double timestamp,
                                    const struct parsed_packet *packet) {
    PyObject *ts_obj;
    PyObject *src_obj;
    PyObject *dst_obj;
    PyObject *proto_obj;
    PyObject *src_port_obj;
    PyObject *dst_port_obj;
    PyObject *tuple;

    ts_obj = PyFloat_FromDouble(timestamp);
    src_obj = PyUnicode_FromString(packet->src_ip);
    dst_obj = PyUnicode_FromString(packet->dst_ip);
    proto_obj = PyUnicode_FromString(packet->protocol_name);
    src_port_obj = packet->has_ports
        ? PyLong_FromUnsignedLong(packet->src_port)
        : Py_NewRef(Py_None);
    dst_port_obj = packet->has_ports
        ? PyLong_FromUnsignedLong(packet->dst_port)
        : Py_NewRef(Py_None);

    if (!ts_obj || !src_obj || !dst_obj || !proto_obj ||
        !src_port_obj || !dst_port_obj) {
        Py_XDECREF(ts_obj);
        Py_XDECREF(src_obj);
        Py_XDECREF(dst_obj);
        Py_XDECREF(proto_obj);
        Py_XDECREF(src_port_obj);
        Py_XDECREF(dst_port_obj);
        return NULL;
    }

    tuple = PyTuple_New(6);
    if (!tuple) {
        Py_DECREF(ts_obj);
        Py_DECREF(src_obj);
        Py_DECREF(dst_obj);
        Py_DECREF(proto_obj);
        Py_DECREF(src_port_obj);
        Py_DECREF(dst_port_obj);
        return NULL;
    }

    PyTuple_SET_ITEM(tuple, 0, ts_obj);
    PyTuple_SET_ITEM(tuple, 1, src_obj);
    PyTuple_SET_ITEM(tuple, 2, dst_obj);
    PyTuple_SET_ITEM(tuple, 3, proto_obj);
    PyTuple_SET_ITEM(tuple, 4, src_port_obj);
    PyTuple_SET_ITEM(tuple, 5, dst_port_obj);

    return tuple;
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *header,
                           const u_char *packet) {
    struct packet_handler_context *context = (struct packet_handler_context *)user;
    struct parsed_packet parsed;
    enum packet_parse_status status;
    PyObject *tuple;

    if (context->failed) {
        return;
    }

    status = parse_ethernet_ipv4_packet(packet, header->caplen, &parsed);
    if (status != PACKET_PARSE_OK) {
        if (status == PACKET_PARSE_ERROR_INVALID_ARGUMENT) {
            PyErr_SetString(PyExc_RuntimeError, "Internal packet parser error");
            context->failed = 1;
        }
        return;
    }

    tuple = build_packet_tuple(packet_timestamp(header), &parsed);
    if (!tuple) {
        context->failed = 1;
        return;
    }

    if (PyList_Append(context->result, tuple) < 0) {
        context->failed = 1;
    }
    Py_DECREF(tuple);
}

static PyObject *parse_packets(PyObject *self, PyObject *args) {
    const char *filename;
    if (!PyArg_ParseTuple(args, "s", &filename))
        return NULL;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if (!handle) {
        PyErr_SetString(PyExc_OSError, errbuf);
        return NULL;
    }

    int dlt = pcap_datalink(handle);
    if (dlt != DLT_EN10MB) {
        pcap_close(handle);
        PyErr_Format(PyExc_ValueError, "Unsupported datalink type: %d", dlt);
        return NULL;
    }

    PyObject *result = PyList_New(0);
    struct packet_handler_context context;
    int loop_status;

    if (!result) {
        pcap_close(handle);
        return NULL;
    }

    context.result = result;
    context.failed = 0;
    loop_status = pcap_loop(handle, 0, packet_handler, (u_char *)&context);
    if (loop_status == -1) {
        Py_DECREF(result);
        PyErr_SetString(PyExc_OSError, pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }

    pcap_close(handle);
    if (context.failed) {
        Py_DECREF(result);
        return NULL;
    }

    return result;
}

static PyMethodDef PacketParserMethods[] = {
    {"parse_packets", parse_packets, METH_VARARGS,
     "Parse a pcap file and return a list of (timestamp, src_ip, dst_ip, "
     "protocol, src_port, dst_port) tuples."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef pcap_parser_module = {
    PyModuleDef_HEAD_INIT,
    "_pcap_parser",
    NULL,
    -1,
    PacketParserMethods
};

PyMODINIT_FUNC PyInit__pcap_parser(void) {
    return PyModule_Create(&pcap_parser_module);
}

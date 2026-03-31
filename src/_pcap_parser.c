#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* IANA protocol name lookup table */
static const struct {
    uint8_t proto;
    const char *name;
} PROTO_TABLE[] = {
    {1,   "ICMP"},
    {2,   "IGMP"},
    {6,   "TCP"},
    {17,  "UDP"},
    {47,  "GRE"},
    {50,  "ESP"},
    {51,  "AH"},
    {89,  "OSPF"},
    {132, "SCTP"},
    {0,   NULL}   /* sentinel */
};

static const char *proto_name(uint8_t proto, char *buf, size_t buf_size) {
    for (int i = 0; PROTO_TABLE[i].name != NULL; i++) {
        if (PROTO_TABLE[i].proto == proto)
            return PROTO_TABLE[i].name;
    }
    snprintf(buf, buf_size, "Unknown(%u)", (unsigned)proto);
    return buf;
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *header,
                            const u_char *packet) {
    PyObject *result = (PyObject *)user;

    /* Need at least Ethernet header (14 bytes) */
    if (header->caplen < 14)
        return;

    /* Only process IPv4 (EtherType 0x0800) */
    uint16_t ethertype = ((uint16_t)packet[12] << 8) | packet[13];
    if (ethertype != 0x0800)
        return;

    /* Need at least Ethernet + minimal IPv4 header (34 bytes) */
    if (header->caplen < 34)
        return;

    const u_char *ip = packet + 14;
    int ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20 || header->caplen < (uint32_t)(14 + ihl))
        return;

    uint8_t proto_num = ip[9];

    /* Source and destination IPs */
    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, ip + 12, src_str, sizeof(src_str)) == NULL)
        return;
    if (inet_ntop(AF_INET, ip + 16, dst_str, sizeof(dst_str)) == NULL)
        return;

    /* Protocol name */
    char proto_buf[32];
    const char *proto_str = proto_name(proto_num, proto_buf, sizeof(proto_buf));

    /* Timestamp */
    double ts = (double)header->ts.tv_sec + (double)header->ts.tv_usec / 1e6;

    /* Ports: only for non-fragmented TCP/UDP */
    uint16_t frag_offset = (((uint16_t)(ip[6] & 0x1F)) << 8) | ip[7];
    int is_fragment = (frag_offset != 0);

    PyObject *src_port_obj, *dst_port_obj;

    if (!is_fragment && (proto_num == 6 || proto_num == 17) &&
        header->caplen >= (uint32_t)(14 + ihl + 4)) {
        const u_char *l4 = ip + ihl;
        uint16_t sp = ((uint16_t)l4[0] << 8) | l4[1];
        uint16_t dp = ((uint16_t)l4[2] << 8) | l4[3];
        src_port_obj = PyLong_FromLong(sp);
        dst_port_obj = PyLong_FromLong(dp);
        if (!src_port_obj || !dst_port_obj) {
            Py_XDECREF(src_port_obj);
            Py_XDECREF(dst_port_obj);
            return;
        }
    } else {
        Py_INCREF(Py_None);
        Py_INCREF(Py_None);
        src_port_obj = Py_None;
        dst_port_obj = Py_None;
    }

    /* Build Python objects for the tuple items */
    PyObject *ts_obj    = PyFloat_FromDouble(ts);
    PyObject *src_obj   = PyUnicode_FromString(src_str);
    PyObject *dst_obj   = PyUnicode_FromString(dst_str);
    PyObject *proto_obj = PyUnicode_FromString(proto_str);

    if (!ts_obj || !src_obj || !dst_obj || !proto_obj) {
        Py_XDECREF(ts_obj);
        Py_XDECREF(src_obj);
        Py_XDECREF(dst_obj);
        Py_XDECREF(proto_obj);
        Py_DECREF(src_port_obj);
        Py_DECREF(dst_port_obj);
        return;
    }

    /* Build tuple: (timestamp, src_ip, dst_ip, protocol, src_port, dst_port) */
    PyObject *tuple = PyTuple_New(6);
    if (!tuple) {
        Py_DECREF(ts_obj);
        Py_DECREF(src_obj);
        Py_DECREF(dst_obj);
        Py_DECREF(proto_obj);
        Py_DECREF(src_port_obj);
        Py_DECREF(dst_port_obj);
        return;
    }

    /* PyTuple_SET_ITEM steals the reference */
    PyTuple_SET_ITEM(tuple, 0, ts_obj);
    PyTuple_SET_ITEM(tuple, 1, src_obj);
    PyTuple_SET_ITEM(tuple, 2, dst_obj);
    PyTuple_SET_ITEM(tuple, 3, proto_obj);
    PyTuple_SET_ITEM(tuple, 4, src_port_obj);
    PyTuple_SET_ITEM(tuple, 5, dst_port_obj);

    PyList_Append(result, tuple);  /* does not steal ref */
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
    if (!result) {
        pcap_close(handle);
        return NULL;
    }

    pcap_loop(handle, 0, packet_handler, (u_char *)result);
    pcap_close(handle);

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

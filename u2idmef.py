from __future__ import print_function

import sys
import os
import os.path
import base64
from lxml import etree

if sys.argv[0] == __file__:
    sys.path.insert(
        0, os.path.abspath(os.path.join(__file__, "..", "..", "..")))
import socket
import time
import logging
from datetime import datetime
try:
    from collections import OrderedDict
except ImportError as err:
    from idstools.compat.ordereddict import OrderedDict

try:
    import argparse
except ImportError as err:
    from idstools.compat.argparse import argparse

from idstools import unified2
from idstools import maps

logging.basicConfig(level=logging.INFO, format="%(message)s")
LOG = logging.getLogger()

proto_map = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

def get_tzoffset(sec):
    offset = datetime.fromtimestamp(sec) - datetime.utcfromtimestamp(sec)
    if offset.days == -1:
        return "-%02d%02d" % (
            (86400 - offset.seconds) / 3600, (86400 - offset.seconds) % 3600)
    else:
        return "+%02d%02d" % (
            offset.seconds / 3600, offset.seconds % 3600)


def render_timestamp(sec, usec):
    tt = time.localtime(sec)
    return "%04d-%02d-%02dT%02d:%02d:%02d.%06d%s" % (
        tt.tm_year, tt.tm_mon, tt.tm_mday, tt.tm_hour, tt.tm_min, tt.tm_sec, usec, get_tzoffset(sec))


class IdmefFilter(object):

    def __init__(
            self, msgmap=None, classmap=None):
        self.msgmap = msgmap
        self.classmap = classmap

    def filter(self, event):
        output = OrderedDict()

        output["analyzer_id"] = event["sensor-id"]
        output["message_id"] = event["event-id"]

        output["ntpstamp"] = render_timestamp(
            event["event-second"], event["event-microsecond"])

        output["severity"] = event["priority"]
        if event["priority"] == 3:
            output["severity"] = 1
        elif event["priority"] == 1:
            output["severity"] = 3

        if socket.inet_aton(event["source-ip"]):
            output["src_category"] = "ipv4-addr"
            output["src_address"] = event["source-ip"]
        elif socket.inet_pton(socket.AF_INET6, event["source-ip"]):
            output["src_category"] = "ipv6-addr"
            output["src_address"] = event["source-ip"]

        if socket.inet_aton(event["destination-ip"]):
            output["dest_category"] = "ipv4-addr"
            output["dest_address"] = event["destination-ip"]
        elif socket.inet_pton(socket.AF_INET6, event["destination-ip"]):
            output["dest_category"] = "ipv6-addr"
            output["dest_address"] = event["destination-ip"]

        if event["protocol"] in [socket.IPPROTO_UDP, socket.IPPROTO_TCP]:
            output["src_port"] = event["sport-itype"]
        else:
            output["src_port"] = None

        if event["protocol"] in [socket.IPPROTO_UDP, socket.IPPROTO_TCP]:
            output["dest_port"] = event["dport-icode"]
        else:
            output["dest_port"] = None

        if event["protocol"] in [socket.IPPROTO_ICMP]:
            output["src_iana_protocol_name"] = "ICMP"
            output["src_iana_protocol_number"] = event["sport-itype"]
            output["dest_iana_protocol_name"] = "ICMP"
            output["dest_iana_protocol_number"] = event["dport-icode"]
        else:
            output["src_iana_protocol_name"] = None
            output["src_iana_protocol_number"] = None
            output["dest_iana_protocol_name"] = None
            output["dest_iana_protocol_number"] = None

        output["src_protocol"] = self.getprotobynumber(event["protocol"])
        output["completion"] = 1 if event["impact-flag"] > 0 else 0
        output["category"] = "block-installed" if event["blocked"] == 1 else "allowed"
        output["src_vlan_id"] = event["vlan-id"]

        output["text"] = self.resolve_classification(event)
        #output["origin"]
        #output["name"]

        addata_sid = OrderedDict()

        addata_sid["meaning"] = "signature-id"
        addata_sid["type"] = 4
        addata_sid["value"] = event["signature-id"]

        output["addData_sid"] = addata_sid

        addata_gid = OrderedDict()

        addata_gid["meaning"] = "generator-id"
        addata_gid["type"] = 4
        addata_gid["value"] = event["generator-id"]

        output["addData_gid"] = addata_gid

        addata_res = OrderedDict()

        addata_res["meaning"] = "signature-revision"
        addata_res["type"] = 4
        addata_res["value"] = event["signature-revision"]

        output["addData_res"] = addata_res

        if event["packets"]:
            output["packet"] = base64.b64encode(event["packets"][0]["data"])

        return output

    def resolve_classification(self, event, default=None):
        if self.classmap:
            classinfo = self.classmap.get(event["classification-id"])
            if classinfo:
                return classinfo["description"]
        return default

    def getprotobynumber(self, protocol):
        return proto_map.get(protocol, str(protocol))


class OutputWrapper(object):

    def __init__(self, filename, fileobj=None):
        self.filename = filename
        self.fileobj = fileobj

        if self.fileobj is None:
            self.reopen()
            self.isfile = True
        else:
            self.isfile = False

    def reopen(self):
        if self.fileobj:
            self.fileobj.close()
        self.fileobj = open(self.filename, "ab")

    def write(self, buf):
        if self.isfile:
            if not os.path.exists(self.filename):
                self.reopen()
        self.fileobj.write(buf)
        self.fileobj.write("\n")
        self.fileobj.flush()

def load_from_snort_conf(snort_conf, classmap, msgmap):
    snort_etc = os.path.dirname(os.path.expanduser(snort_conf))

    classification_config = os.path.join(snort_etc, "classification.config")
    if os.path.exists(classification_config):
        LOG.debug("Loading %s.", classification_config)
        classmap.load_from_file(open(classification_config))

    genmsg_map = os.path.join(snort_etc, "gen-msg.map")
    if os.path.exists(genmsg_map):
        LOG.debug("Loading %s.", genmsg_map)
        msgmap.load_generator_map(open(genmsg_map))

    sidmsg_map = os.path.join(snort_etc, "sid-msg.map")
    if os.path.exists(sidmsg_map):
        LOG.debug("Loading %s.", sidmsg_map)
        msgmap.load_signature_map(open(sidmsg_map))

def idmef_xml(output):

    root = etree.Element("IDMEF-Message", xmlns="http://www.iana.org/idmef", version="1.0")
    alert = etree.SubElement(root, "Alert", messageid=str(output["message_id"]))
    analyzer = etree.SubElement(alert, "Analyzer", analyzerid=str(output["analyzer_id"]))

    createtime = etree.SubElement(alert, "CreateTime")
    createtime.text = output["ntpstamp"]

    source = etree.SubElement(alert, "Source")
    snode = etree.SubElement(source, "Node")
    saddress = etree.SubElement(snode, "Address", category=str(output["src_category"]), vlan_name=str(output["src_vlan_id"]))
    saddr = etree.SubElement(saddress, "address")
    saddr.text = output["src_address"]
    sservice = etree.SubElement(source, "Service", protocol=output["src_protocol"], port=str(output["src_port"]), iana_protocol_name=output["src_iana_protocol_name"], iana_protocol_number=str(output["src_iana_protocol_number"]))

    target = etree.SubElement(alert, "Target")
    tnode = etree.SubElement(target, "Node")
    taddress = etree.SubElement(tnode, "Address", category=str(output["dest_category"]))
    taddr = etree.SubElement(taddress, "address")
    taddr.text = output["dest_address"]
    tservice = etree.SubElement(source, "Service", port=str(output["dest_port"]))

    classification = etree.SubElement(alert, "Classification", text=output["text"])
    reference = etree.SubElement(classification, "Reference") #origin=output["origin"], name=output["name"]
    assessment = etree.SubElement(classification, "Assessment")
    impact = etree.SubElement(assessment, "Impact", severity=str(output["severity"]), completion=str(output["completion"]))
    action = etree.SubElement(assessment, "Action", category=str(output["category"]))

    adddatasid = etree.SubElement(alert, "TheAdditionalData", meaning=str(output["addData_sid"]["meaning"]),
                               type=str(output["addData_sid"]["type"]),
                               value=str(output["addData_sid"]["value"]))
    adddatagid = etree.SubElement(alert, "TheAdditionalData", meaning=str(output["addData_gid"]["meaning"]),
                               type=str(output["addData_gid"]["type"]),
                               value=str(output["addData_gid"]["value"]))
    adddatares = etree.SubElement(alert, "TheAdditionalData", meaning=str(output["addData_res"]["meaning"]),
                               type=str(output["addData_res"]["type"]),
                               value=str(output["addData_res"]["value"]))

    return root

epilog = """If --directory and --prefix are provided files will be
read from the specified 'spool' directory.  Otherwise files on the
command line will be processed.
"""

def main():

    msgmap = maps.SignatureMap()
    classmap = maps.ClassificationMap()

    parser = argparse.ArgumentParser(
        fromfile_prefix_chars='@', epilog=epilog)
    parser.add_argument(
        "-C", dest="classification_path", metavar="<classification.config>",
        help="path to classification config")
    parser.add_argument(
        "-S", dest="sidmsgmap_path", metavar="<msg-msg.map>",
        help="path to sid-msg.map")
    parser.add_argument(
        "-G", dest="genmsgmap_path", metavar="<gen-msg.map>",
        help="path to gen-msg.map")
    parser.add_argument(
        "--snort-conf", dest="snort_conf", metavar="<snort.conf>",
        help="attempt to load classifications and map files based on the "
             "location of the snort.conf")
    parser.add_argument(
        "--directory", metavar="<spool directory>",
        help="spool directory (eg: /var/log/snort)")
    parser.add_argument(
        "--prefix", metavar="<spool file prefix>",
        help="spool filename prefix (eg: unified2.log)")
    parser.add_argument(
        "--bookmark", action="store_true", default=False,
        help="enable bookmarking")
    parser.add_argument(
        "--follow", action="store_true", default=False,
        help="follow files/continuous mode (spool mode only)")
    parser.add_argument(
        "--delete", action="store_true", default=False,
        help="delete spool files")
    parser.add_argument(
        "--output", metavar="<filename>",
        help="output filename (eg: /var/log/snort/alerts.xml")
    parser.add_argument(
        "--stdout", action="store_true", default=False,
        help="also log to stdout if --output is a file")
    parser.add_argument(
        "filenames", nargs="*")
    args = parser.parse_args()

    if args.snort_conf:
        load_from_snort_conf(args.snort_conf, classmap, msgmap)

    if args.classification_path:
        classmap.load_from_file(
            open(os.path.expanduser(args.classification_path)))
    else:   #test
        classmap.load_from_file(open("classification.config"))
    if args.genmsgmap_path:
        msgmap.load_generator_map(open(os.path.expanduser(args.genmsgmap_path)))
    else:   #test
        msgmap.load_generator_map(open("gen-msg.map"))
    if args.sidmsgmap_path:
        msgmap.load_signature_map(open(os.path.expanduser(args.sidmsgmap_path)))
    else:   #test
        msgmap.load_signature_map(open("community-sid-msg.map"))

    if msgmap.size() == 0:
        print("WARNING: No alert message map entries loaded.")
    else:
        print("Loaded %s rule message map entries.", msgmap.size())

    if classmap.size() == 0:
        print("WARNING: No classifications loaded.")
    else:
        print("Loaded %s classifications.", classmap.size())

    idmef_filter = IdmefFilter(msgmap, classmap)

    outputs = []

    if args.output:
        outputs.append(OutputWrapper(args.output))
        if args.stdout:
            outputs.append(OutputWrapper("-", sys.stdout))
    else:
        outputs.append(OutputWrapper("-", sys.stdout))

    if args.directory and args.prefix:
        reader = unified2.SpoolEventReader(
            directory=args.directory,
            prefix=args.prefix,
            follow=args.follow,
            delete=args.delete,
            bookmark=args.bookmark)
    elif args.filenames:
        reader = unified2.FileEventReader(*args.filenames)
    else:
        print("nothing to do.")
        return

    for event in reader:
        try:
            handle = etree.tostring( idmef_xml(idmef_filter.filter(event)), pretty_print=True,
                                     encoding='utf-8', xml_declaration=True)
            for out in outputs:
                out.write(handle)
        except Exception as err:
            LOG.error("Failed to write file record as IDMEF: %s: %s" % (
                str(err), str(event)))

if __name__ == "__main__":
    sys.exit(main())


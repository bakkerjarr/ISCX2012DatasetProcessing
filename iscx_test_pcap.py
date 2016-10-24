# Copyright 2016 Jarrod N. Bakker
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from lxml import etree
import dpkt
import os

__author__ = "Jarrod N. Bakker"
__status__ = "Development"

RAND_SEED = 99999999


class ISCXSplit:
    """This class takes care of creating a PCAP file comprised of
    selected traffic from the ISCX 2012 DDoS dataset. Traffic is
    selected using the summary of flows from a XML file.

    WARNING: The original PCAP file containing the DDoS traffic is 
    roughly 24GB in size. Processing the file will take a while.
    """

    def __init__(self, pcap_file, input_dir, files):
        """Initialise.

        :param pcap_file: PCAP file containing ISCX 2012 DDoS dataset
        packets.
        :param input_dir: Directory of the XML dataset files.
        :param files: List of files to read in.
        """
        self._pcap = pcap_file
        self._input_dir = input_dir
        self._files = files
        self._raw_data = []

    def create_pcap(self, output_pcap):
        """Read in the ISCX 2012 DDoS dataset file/s and create PCAP
        files by picking packets matching flows within the dataset fles.
        k-fold training and testing sets.

        :param output_pcap: Path for the new PCAP file.
        """
        self._load_data()
        self._filter_pcap(output_pcap)
        print("Exiting...")

    def _load_data(self):
        """Read in the ISCX 2012 DDoS dataset and store the data.
        """
        print("Loading ISCX 2012 DDoS dataset...")
        for fname in self._files:
            path = os.path.join(self._input_dir, fname)
            raw_data = self._read_data(path)
            self._raw_data.extend(raw_data)

    def _read_data(self, fname):
        """Read data from an ISCX dataset XML.

        :param fname: Name of the file to read the data from.
        :return: The data.
        """
        print("\tReading data from: {0}".format(fname))
        data_etree = etree.parse(fname)
        raw_data = self._etree_to_dict(data_etree)
        print("\t\tLoading complete.")
        return raw_data

    def _etree_to_dict(self, etree):
        """Convert an XML etree into a list of dicts.

        This method only takes care of elements, not attributes!

        :param etree: Etree object to process
        :return: Data as a list of dict.
        """
        root = etree.getroot()
        data = []
        for flow in root:
            flow_data = {}
            for i in range(len(flow)):
                flow_data[flow[i].tag] = flow[i].text
            data.append(flow_data)
        return data

    def _filter_pcap(self, output_pcap):
        """Using a provided file with XML flow summaries, create a
        new PCAP file with the flows in the XML file.

        :param output_pcap: Path for the new PCAP file.
        """
        try:
            print("Opening file: {0}".format(self._pcap))
            f = open(self._pcap)
            raw_pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                # Loop through packets in PCAP file
                pass
                # TODO: Does this packet match a flow in the raw data?
                # TODO: Append packet data to new PCAP file.
        except:
            print("ERROR reading from file: {0}".format(self._pcap))

    
if __name__ == "__main__":
    pcap_file = "/local/scratch/bakkerjarr/Datasets/ISCXIDS2012/" \
                    "testbed-15jun.pcap"
    input_dir = "/local/scratch/bakkerjarr/Datasets/" \
                    "ISCX2012DDoS_5-fold_sets/test/"
    files = ["iscx2012ddos_testing_set_fold_1.xml"]#,
             # "iscx2012ddos_testing_set_fold_2.xml",
             # "iscx2012ddos_testing_set_fold_3.xml",
             # "iscx2012ddos_testing_set_fold_4.xml",
             # "iscx2012ddos_testing_set_fold_5.xml"]
    working_dir = os.path.dirname(__file__)
    output_pcap = "iscx2012ddos_testing_pcap_fold_1.xml"
    split = ISCXSplit(pcap_file, input_dir, files)
    split.create_pcap(output_pcap)

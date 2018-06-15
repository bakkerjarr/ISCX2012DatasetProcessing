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
from sklearn.cross_validation import StratifiedKFold
import os

__author__ = "Jarrod N. Bakker"
__status__ = "Development"

RAND_SEED = 99999999


class ISCXSplit:
    """This class takes care of splitting the ISCX 2012 DDoS dataset.

    The resulting training and testing sets are k-fold stratified in
    regards to the proportion of 'Normal' and 'Attack' cases. The
    StratifiedKFold class from the sklearn package is used.

    NOTE: The training set is traditionally larger than the testing
    set in k-fold cross validation. This means that you train with k-1
    folds and test with 1 fold. However this class switches the two
    around so that the training set is small enough to allow a SVM to
    train within a reasonable amount of time. This is only an issue as
    the dataset contains 571698 cases. 534238 represent normal cases
    and 37460 represent attack cases (checked 20/10/2016).
    """

    _XML_DOCTYPE = '<?xml version="1.0" encoding="UTF-8"?>'

    def __init__(self, folds, input_dir, files):
        """Initialise.

        :param folds: The desired number of folds.
        :param input_dir: Directory of the XML dataset files.
        :param files: List of files to read in.
        """
        self._folds = folds
        self._input_dir = input_dir
        self._files = files
        self._raw_data = []
        self._labels = []

    def create_sets(self, output_dir):
        """Read in the ISCX 2012 DDoS dataset and create stratified
        k-fold training and testing sets.

        The created training and testing sets are written to separate
        directories.

        :param output_dir: Directory for the created training and
        testing sets to be written to.
        """
        self._load_data()
        kfold = self._calc_kfold(self._labels)
        self._save_sets(kfold, output_dir)

    def _load_data(self):
        """Read in the ISCX 2012 DDoS dataset and store the data and
        the labels.
        """
        print("Loading ISCX 2012 DDoS dataset...")
        for fname in self._files:
            path = os.path.join(self._input_dir, fname)
            raw_data, raw_labels = self._read_data(path)
            self._raw_data.extend(raw_data)
            self._labels.extend(raw_labels)

    def _read_data(self, fname):
        """Read data from an ISCX dataset XML.

        :param fname: Name of the file to read the data from.
        :return: The data and labels.
        """
        print("\tReading data from: {0}".format(fname))
        data_etree = etree.parse(fname)
        raw_data, raw_labels = self._etree_to_dict(data_etree)
        print("\t\tLoading complete.")
        return raw_data, raw_labels

    def _etree_to_dict(self, etree):
        """Convert an XML etree into a list of dicts.

        This method only takes care of elements, not attributes!

        :param etree: Etree object to process
        :return: Data as a list of dict.
        """
        root = etree.getroot()
        data = []
        labels = []
        for flow in root:
            flow_data = {}
            for i in range(len(flow)):
                flow_data[flow[i].tag] = flow[i].text
                if flow[i].tag == "Tag":
                    if flow[i].text == "Normal":
                        labels.append(TagValue.Normal)
                    else:
                        labels.append(TagValue.Attack)
            data.append(flow_data)
        return data, labels

    def _calc_kfold(self, labels):
        """Calculate k stratified folds.

        :param labels: The labels for the dataset elements.
        :return: StratifiedKFold object representing what dataset
        elements belong in each fold.
        """
        print("Calculating {0} stratified folds...".format(self._folds))
        kfold = StratifiedKFold(labels, n_folds=self._folds,
                                shuffle=True, random_state=RAND_SEED)
        print("\tFold calculation complete.")
        return kfold

    def _save_sets(self, kfold, output_dir):
        """Save training and testing set files using k-fold information.

        :param kfold: Object indicating what elements should be in
        what set.
        :param output_dir: Parent directory for the resulting sets.
        """
        # Create the parent directory if it doesn't already exist.
        if not os.path.exists(output_dir):
            print("Creating parent directory for the training and "
                  "testing sets...")
            os.mkdir(output_dir)
        else:
            print("Parent directory for the training and testing sets "
                  "already exists. Continuing...")
        # Create directories for storing the different training and
        # testing sets.
        train_dir = os.path.join(output_dir, "train")
        if not os.path.exists(train_dir):
            print("Creating directory for the training set...")
            os.mkdir(train_dir)
        else:
            print("Parent directory for the training set already "
                  "exists. Continuing...")
        test_dir = os.path.join(output_dir, "test")
        if not os.path.exists(test_dir):
            print("Creating directory for the test set...")
            os.mkdir(test_dir)
        else:
            print("Parent directory for the test set already exists. "
                  "Continuing...")
        # Loop through all training and testing sets and create
        # matching files.
        fold = 1
        for train, test in kfold:
            train_set = {"training_set_{0}".format(fold): map(
                self._raw_data.__getitem__, test)}
            test_set = {"testing_set_{0}".format(fold): map(
                self._raw_data.__getitem__, train)}
            train_file = os.path.join(train_dir,
                                      "iscx2012ddos_training_set_fold_"
                                      "{0}.xml".format(fold))
            test_file = os.path.join(test_dir,
                                      "iscx2012ddos_testing_set_fold_"
                                      "{0}.xml".format(fold))
            print("Serialising data for training set {0}.".format(fold))
            train_xml = self._serialise_to_xml(train_set)
            with open(train_file, mode="w") as t_file:
                print("Writing to file: {0}".format(train_file))
                t_file.write(train_xml)
            print("Serialising data for testing set {0}.".format(fold))
            test_xml = self._serialise_to_xml(test_set)
            with open(test_file, mode="w") as t_file:
                print("Writing to file: {0}".format(test_file))
                t_file.write(test_xml)
            fold += 1

    def _serialise_to_xml(self, raw_dict):
        """Turn a dictionary into an XML string.

        Adapted from code from https://gist.github.com/dolph/1792904.
        Accessed 20/10/2016.

        :param raw_dict: The dictionary to convert.
        :return: String representation of the XML.
        """
        root = etree.Element("dataroot")
        self._populate_element(root, raw_dict)
        return "{0}\n{1}".format(self._XML_DOCTYPE, etree.tostring(
            root, pretty_print=True))

    def _populate_element(self, root, d):
        """Populates an etree with the given dictionary.

        Adapted from code from https://gist.github.com/dolph/1792904.
        Accessed 20/10/2016.

        :param root: root XML element to append to.
        :param d: Data to convert.
        :return: An etree encoded XML object.
        """
        for tset_name, data in d.iteritems():
            for elem in data:
                child = etree.Element(tset_name)
                for k, v in elem.iteritems():
                    data = etree.Element(k)
                    data.text = v
                    child.append(data)
                root.append(child)


class TagValue:
    """Enum for the dataset tag labels.
    """
    Normal = 0
    Attack = 1

if __name__ == "__main__":
    folds = 5
    input_dir = "/vol/nerg-solar/bakkerjarr/Datasets/ISCXIDS2012" \
                    "/labeled_flows_xml/"
    files = ["TestbedTueJun15-1Flows.xml",
             "TestbedTueJun15-2Flows.xml",
             "TestbedTueJun15-3Flows.xml"]
    working_dir = os.path.dirname(__file__)
    output_dir = os.path.join(working_dir, "ISCX2012DDoS_{0}-fold_sets".format(folds))
    split = ISCXSplit(folds, input_dir, files)
    split.create_sets(output_dir)

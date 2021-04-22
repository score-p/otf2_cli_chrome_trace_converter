import argparse
import gzip
import json
import os
import shutil

import otf2

TIMER_GRANULARITY = 1000000  # chrome traces uses micro seconds


def is_gzip_file(path):
    try:
        file = gzip.open(self._trace_file)
        file.read(1)
        return True
    except Exception:
        return False


class TensorFlowTrace2OTF2:

    def __init__(self, input_path):
        if not input_path or not os.path.exists(input_path):
            raise Exception("Specified location does not exist:", input_path)

        input_file = None
        if os.path.isfile(input_path):
            input_file = input_path
        elif os.path.isdir(input_path):
            for root, dirs, files in os.walk(input_path):
                for filename in files:
                    if filename.endswith('.trace.json.gz') or filename.endswith('.trace.json'):
                        if input_file is None:
                            input_file = os.path.join(root, filename)
                        else:
                            raise Exception("Found multiple chrome traces. Please specify the file or folder directly!")
        if not input_file:
            raise Exception("No chrome trace found")

        self._trace_file = input_file
        self._process_map = {}
        self._function_map = {}
        self._metric_map = {}
        self._dataflow_start = None

    def convert_trace(self, output_dir):
        if not output_dir:
            raise Exception("No output trace")

        with gzip.open(self._trace_file) if is_gzip_file(self._trace_file) else open(self._trace_file) as json_file, \
             otf2.writer.open(output_dir, timer_resolution=TIMER_GRANULARITY) as otf2_trace:
            chrome_data = json.load(json_file)

            otf2_root_node = otf2_trace.definitions.system_tree_node("root node")
            otf2_system_tree_node = otf2_trace.definitions.system_tree_node("myHost", parent=otf2_root_node)

            for chrome_event in chrome_data['traceEvents']:

                # Metadata Events
                if chrome_event['ph'] == 'M' and chrome_event['name'] == 'process_name':
                    self._handle_metadata(chrome_event, otf2_system_tree_node, otf2_trace)

                # Complete Events, TensorFlow seems to not use B and E events
                elif chrome_event['ph'] == 'X' and ( 'cat' not in chrome_event or chrome_event['cat'] == "Op" ):
                    self._handle_event(chrome_event, otf2_trace)

                # Counter Events
                elif chrome_event['ph'] == 'C':
                    self._handle_metric(chrome_event, otf2_trace)

                # Flow Events (start, step, end)
                elif chrome_event['ph'] in ['s', 't', 'f']:
                    self._handle_dataflow(chrome_event)

                else:
                    print("untrackt event found: {}".format(chrome_event))

    #TODO Map newly created processes for only collecting one metric to process with same name
    def _handle_metric(self, chrome_event, otf2_trace):
        metric_name = chrome_event['name']
        cpid = chrome_event['pid']
        ctid = chrome_event['tid']
        if metric_name == 'Allocated Bytes':
            if chrome_event['name'] not in self._metric_map:
                self.otf2_add_metric(otf2_trace, metric_name, 'Bytes')

            if ctid >= len(self._process_map[cpid]['threads']):
                self._otf2_add_thread(ctid, cpid, otf2_trace)

            metric_value = chrome_event['args']['Allocator Bytes in Use']
            otf2_thread = self._process_map[cpid]['threads'][ctid]
            otf2_thread.metric(chrome_event['ts'], self._metric_map[metric_name], metric_value)

    def otf2_add_metric(self, otf2_trace, name, unit):
        metric = otf2_trace.definitions.metric(name, unit=unit)
        self._metric_map[name] = metric

    def _handle_metadata(self, chrome_event, otf2_system_tree_node, otf2_trace):
        otf2_location_group = otf2_trace.definitions.location_group(chrome_event['args']['name'],
                                                                    system_tree_parent=otf2_system_tree_node)
        self._process_map[chrome_event['pid']] = {'location': otf2_location_group, 'threads': [],
                                                  'name': chrome_event['args']['name']}

    def _handle_event(self, chrome_event, otf2_trace):
        cpid = chrome_event['pid']
        ctid = chrome_event['tid']
        if ctid >= len(self._process_map[cpid]['threads']):
            self._otf2_add_thread(ctid, cpid, otf2_trace)

        if not chrome_event['name'] in self._function_map:
            self._otf2_add_function(chrome_event['name'], otf2_trace)

        otf2_thread = self._process_map[cpid]['threads'][ctid]
        otf2_function = self._function_map[chrome_event['name']]

        begin = chrome_event['ts']
        end = (begin + chrome_event['dur'])

        otf2_thread.enter(begin, otf2_function)
        otf2_thread.leave(end, otf2_function)

    def _otf2_add_thread(self, ctid, cpid, otf2_trace):
        otf2_location_group = self._process_map[cpid]['location']
        otf2_thread = otf2_trace.event_writer(
            str(self._process_map[cpid]['name']) + str(ctid),
            group=otf2_location_group)
        self._process_map[cpid]['threads'].append(otf2_thread)

    def _otf2_add_function(self, name, otf2_trace):
        otf2_function = otf2_trace.definitions.region(name, paradigm=otf2.Paradigm.USER)
        self._function_map[name] = otf2_function

    # TODO implementation of dataflow
    def _handle_dataflow(self, chrome_event):
        if chrome_event['ph'] == 's':
            if self._dataflow_start is not None:
                print("corrupted trace in dataflow: {}".format(chrome_event))
                self._dataflow_start = None
            self._dataflow_start = chrome_event['id']
            # dataflow handling

        elif chrome_event['ph'] == 't':
            if self._dataflow_start != chrome_event['id']:
                print("corrupted trace in dataflow: {}".format(chrome_event))
            # dataflow handling

            self._dataflow_start = None


def cli():
    parser = argparse.ArgumentParser(description="Convert chrome traces into OTF2")
    parser.add_argument(
        "-i", "--input",
        type=str, required=True,
        help="chrome tracing file",
    )
    parser.add_argument(
        "-o", "--output",
        type=str, required=True,
        help="OTF2 Tracing folder",
    )
    parser.add_argument(
        "-c", "--clean",
        action="store_true",
        help="Clean (delete) the output folder if it exists",
    )
    args = parser.parse_args()

    out_folder = args.output
    if args.clean and os.path.exists(out_folder):
        shutil.rmtree(out_folder)

    converter = TensorFlowTrace2OTF2(args.input)
    converter.convert_trace(out_folder)


if __name__ == '__main__':
    cli()

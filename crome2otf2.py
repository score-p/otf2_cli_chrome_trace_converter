import argparse
import json
import os
import shutil

import otf2

TIMER_GRANULARITY = 1000000  # chrome traces uses micro seconds


class TensorFlowTrace2OTF2:

    def __init__(self, input_file):
        if not input or not os.path.isfile(input_file):
            raise Exception("No chrome trace found")

        self._input_file = input_file
        self._process_map = {}
        self._function_map = {}
        self._dataflow_start = None

    def convert_trace(self, output_dir):
        if not output_dir:
            raise Exception("No output trace")

        with open(self._input_file) as json_file:
            chrome_data = json.load(json_file)
            with otf2.writer.open(output_dir,
                                  timer_resolution=TIMER_GRANULARITY) as otf2_trace:
                otf2_root_node = otf2_trace.definitions.system_tree_node("root node")
                otf2_system_tree_node = otf2_trace.definitions.system_tree_node("myHost", parent=otf2_root_node)

                for chrome_event in chrome_data['traceEvents']:

                    # Metadata Events
                    if chrome_event['ph'] == 'M' and chrome_event['name'] == 'process_name':
                        self.handle_metadata(chrome_event, otf2_system_tree_node, otf2_trace)

                    # Complete Events, TensorFlow seems to not use B and E events
                    elif chrome_event['ph'] == 'X' and chrome_event['cat'] == "Op":
                        self.handle_event(chrome_event, otf2_trace)

                    # Counter Events
                    elif chrome_event['ph'] == 'C':
                        pass
                    
                    # Flow Events (start, step, end)
                    elif chrome_event['ph'] in ['s', 't', 'f']:
                        self.handle_dataflow(chrome_event)

                    else:
                        print("untrackt event found: {}".format(chrome_event))

    def handle_metadata(self, chrome_event, otf2_system_tree_node, otf2_trace):
        otf2_location_group = otf2_trace.definitions.location_group(chrome_event['args']['name'],
                                                                    system_tree_parent=otf2_system_tree_node)
        self._process_map[chrome_event['pid']] = {'location': otf2_location_group, 'threads': [],
                                                  'name': chrome_event['args']['name']}

    def handle_event(self, chrome_event, otf2_trace):
        chrome_process_id = chrome_event['pid']
        chrome_thread_id = chrome_event['tid']
        if chrome_thread_id >= len(self._process_map[chrome_process_id]['threads']):
            self.otf2_add_thread(chrome_thread_id, chrome_process_id, otf2_trace)

        if not chrome_event['name'] in self._function_map:
            self.otf2_add_function(chrome_event['name'], otf2_trace)

        otf2_thread = self._process_map[chrome_process_id]['threads'][chrome_thread_id]
        otf2_function = self._function_map[chrome_event['name']]

        begin = chrome_event['ts']
        end = (begin + chrome_event['dur'])

        otf2_thread.enter(begin, otf2_function)
        otf2_thread.leave(end, otf2_function)

    def otf2_add_thread(self, chrome_thread_id, chrome_process_id, otf2_trace):
        otf2_location_group = self._process_map[chrome_process_id]['location']
        otf2_thread = otf2_trace.event_writer(
            str(self._process_map[chrome_process_id]['name']) + str(chrome_thread_id),
            group=otf2_location_group)
        self._process_map[chrome_process_id]['threads'].append(otf2_thread)

    def otf2_add_function(self, name, otf2_trace):
        otf2_function = otf2_trace.definitions.region(name, paradigm=otf2.Paradigm.USER)
        self._function_map[name] = otf2_function

    # TODO implementation of dataflow
    def handle_dataflow(self, chrome_event):
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


def main():
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
    main()

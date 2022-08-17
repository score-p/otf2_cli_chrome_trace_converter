#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import copy
import gzip
import json
import os
import shutil

from dataclasses import dataclass, field
from typing import Dict, Optional

import otf2

TIMER_GRANULARITY = int(1e9)  # chrome traces uses micro seconds but has precision up to nanoseconds in TF2!


@dataclass
class Process:
    name: str
    group: otf2.definitions.LocationGroup
    threads: Dict[int, otf2.definitions.Location] = field(default_factory=dict)


def is_gzip_file(path):
    try:
        file = gzip.open(path)
        file.read(1)
        return True
    except Exception:
        return False


class ChromeTrace2OTF2:
    def __init__(self, input_path: str, memory_profile_path: Optional[str] = None) -> None:
        """
        input_path : A path to a folder containing a "<hostname>.memory_profile.json.gz" and
                     "<hostname>.trace.json.gz" or path to the latter directly.
        memory_profile_path : Path to the "<hostname>.memory_profile.json.gz". If input_path
                     is a folder and this is not set, then search in the folder for this file.
        """

        if not input_path or not os.path.exists(input_path):
            raise Exception("Specified location does not exist:", input_path)

        if memory_profile_path and not os.path.exists(memory_profile_path):
            raise Exception("Specified memory profile location does not exist:", memory_profile_path)

        self._trace_file: Optional[str] = None
        self._memory_trace_file = memory_profile_path

        if os.path.isfile(input_path):
            self._trace_file = input_path
        elif os.path.isdir(input_path):
            for root, _, files in os.walk(input_path):
                for filename in files:
                    if filename.endswith('.trace.json.gz') or filename.endswith('.trace.json'):
                        if self._trace_file is None:
                            self._trace_file = os.path.join(root, filename)
                        else:
                            raise Exception("Found multiple chrome traces. Please specify the file or folder directly!")

                    if filename.endswith('.memory_profile.json.gz') or filename.endswith('.memory_profile.json'):
                        if self._memory_trace_file is None:
                            self._memory_trace_file = os.path.join(root, filename)
                        else:
                            raise Exception(
                                "Found multiple memory profiles. Please specify the file or folder directly!"
                            )

        if not self._trace_file:
            raise Exception("No chrome trace found")

        self._process_map: Dict[int, Process] = {}
        self._function_map: Dict[str, otf2.definitions.Region] = {}
        self._metric_map: Dict[str, otf2.definitions.Metric] = {}
        self._dataflow_start = None

        self._otf2_root_node: Optional[otf2.definitions.SystemTreeNode] = None
        self._otf2_system_tree_host: Optional[otf2.definitions.SystemTreeNode] = None

    def convert_trace(self, output_dir: str) -> None:
        if not output_dir:
            raise Exception("No output trace")
        if not self._trace_file:
            raise Exception("No input trace")

        with otf2.writer.open(output_dir, timer_resolution=TIMER_GRANULARITY) as otf2_trace:
            self._otf2_root_node = otf2_trace.definitions.system_tree_node("root node")
            self._otf2_system_tree_host = otf2_trace.definitions.system_tree_node("myHost", parent=self._otf2_root_node)

            with gzip.open(self._trace_file, 'rb') if is_gzip_file(self._trace_file) else open(
                self._trace_file, 'rb'
            ) as json_file:
                chrome_data = json.load(json_file)
                self._convert_event_trace(chrome_data, otf2_trace)

            if self._memory_trace_file:
                with gzip.open(self._memory_trace_file, 'rb') if is_gzip_file(self._memory_trace_file) else open(
                    self._memory_trace_file, 'rb'
                ) as json_file:
                    memory_data = json.load(json_file)
                    self._convert_memory_profile(memory_data, otf2_trace)

    def _convert_event_trace(self, chrome_data: Dict, otf2_trace: otf2.writer.Writer) -> None:
        for event in chrome_data['traceEvents']:
            if not event:
                # Trace might contain an empty event at the end for some reason
                pass

            # Metadata Events
            elif event['ph'] == 'M':
                self._handle_metadata(event, self._otf2_system_tree_host, otf2_trace)

            # Flow Events (start, step, end)
            elif event['ph'] in ['s', 't', 'f']:
                self._handle_dataflow(event)

            # Counter Events
            elif event['ph'] == 'C':
                self._handle_metric(event, otf2_trace)

            elif event['ph'] == 'X' and 'ts' in event and 'dur' in event:
                pass  # will be handled separately in order to sort enter leave events by time

            # Complete Events, TensorFlow seems to not use B and E events
            else:
                print(f"Unknown event found: {event}")

        # Split all tracing events of the form 'ts', 'dur' into separate enter leave events.
        sorted_events = []
        for event in chrome_data['traceEvents']:
            if 'ts' in event and 'dur' in event and 'ph' in event and event['ph'] == 'X':
                enter_event = copy.deepcopy(event)
                # The enter events will have the 'dur' key deleted to be recognized!
                del enter_event['dur']
                sorted_events.append(enter_event)
                sorted_events.append(event)

        sorted_events = sorted(sorted_events, key=lambda e: (e['ts'] + (e['dur'] if 'dur' in e else 0)))
        for event in sorted_events:
            if event['ph'] == 'X':
                self._handle_event(event, otf2_trace)

            else:
                print(f"Unknown timestamped event found: {event}")

    def _convert_memory_profile(self, memory_data: Dict, otf2_trace: otf2.writer.Writer) -> None:
        otf2_location_group = otf2_trace.definitions.location_group(
            "TF Memory Allocators", system_tree_parent=self._otf2_system_tree_host
        )

        memory_activities = {}
        otf2_attributes = {}
        uint_metadata = [  # These are some values which are strings in the JSON even though they are integers
            "stackReservedBytes",
            "heapAllocatedBytes",
            "freeMemoryBytes",
            "peakBytesInUse",
            "requestedBytes",
            "allocationBytes",
            "address",
            "stepId",
        ]

        last_leave = None

        for allocator_name, profile in memory_data['memoryProfilePerAllocator'].items():
            location = otf2_trace.event_writer(allocator_name, group=otf2_location_group)

            for snapshot in profile['memoryProfileSnapshots']:
                activity = snapshot['activityMetadata']['memoryActivity']
                if activity not in memory_activities:
                    memory_activities[activity] = otf2_trace.definitions.region(activity, paradigm=otf2.Paradigm.USER)

                event_attributes = copy.deepcopy(snapshot['activityMetadata'])
                event_attributes.update(snapshot['aggregationStats'])

                otf2_event_attributes = {}

                for key, value in event_attributes.items():
                    if key not in otf2_attributes:
                        attribute_type = otf2.Type.STRING
                        if key in uint_metadata:
                            value = int(value)
                            attribute_type = otf2.Type.UINT64
                        elif key is isinstance(value, int):
                            attribute_type = otf2.Type.INT64
                        elif key is isinstance(value, float):
                            attribute_type = otf2.Type.DOUBLE

                        otf2_attributes[key] = otf2_trace.definitions.attribute(name=key, type=attribute_type)

                    otf2_event_attributes[otf2_attributes[key]] = value

                timestamp = int(snapshot['timeOffsetPs']) // 1000  # Time is in picoseconds but precision is nanoseconds
                if last_leave:  # Put the leave at the next enter in order to not create invisible metrics and regions
                    location.leave(timestamp, region=last_leave)
                location.enter(timestamp, memory_activities[activity], attributes=otf2_event_attributes)
                last_leave = memory_activities[activity]

        if last_leave:
            location.leave(timestamp, region=last_leave)

    @staticmethod
    def _convert_time_to_ticks(timestamp: float) -> int:
        """Converts microseconds with 3 decimal places for nanoseconds to nanoseconds (integer)"""
        return int(timestamp * 1e3)

    # TODO Map newly created processes for only collecting one metric to process with same name
    def _handle_metric(self, event: Dict, otf2_trace: otf2.writer.Writer):
        metric_name = event['name']
        pid = event['pid']
        tid = event['tid']
        if metric_name == 'Allocated Bytes':
            if event['name'] not in self._metric_map:
                self.otf2_add_metric(otf2_trace, metric_name, 'Bytes')

            if tid not in self._process_map[pid].threads:
                self._otf2_add_thread(tid, pid, otf2_trace)

            metric_value = event['args']['Allocator Bytes in Use']
            otf2_thread = self._process_map[pid].threads[tid]
            otf2_thread.metric(self._convert_time_to_ticks(event['ts']), self._metric_map[metric_name], metric_value)

    def otf2_add_metric(self, otf2_trace: otf2.writer.Writer, name: str, unit: str) -> None:
        metric = otf2_trace.definitions.metric(name, unit=unit)
        self._metric_map[name] = metric

    def _handle_metadata(
        self, event, otf2_system_tree_node: otf2.definitions.SystemTreeNode, otf2_trace: otf2.writer.Writer
    ) -> None:
        if 'name' in event and event['name'] == 'process_name':
            name = str(event['args']['name']) + str(" ") + str(event['pid'])
            self._otf2_add_process(event['pid'], otf2_trace, otf2_system_tree_node, name)

        elif 'name' in event and event['name'] == 'thread_name':
            pid = event['pid']
            tid = event['tid']
            if pid == 0 and tid == 0:
                # ignore events of system processes, e.g., swapper
                return
            if pid not in self._process_map:
                self._otf2_add_process(
                    pid,
                    otf2_trace,
                    otf2_system_tree_node,
                    f"{event['args']['name']} {event['pid']}",
                )
            assert (
                tid not in self._process_map[event['pid']].threads
            ), "The thread_name metadata event should be the very first event for that thread!"
            name = str(event['args']['name']) + str(" ") + str(event['tid'])
            self._otf2_add_thread(tid, event['pid'], otf2_trace, name)

        else:
            print("Unknown metadata event:", event)

    def _handle_event(self, event: Dict, otf2_trace: otf2.writer.Writer) -> None:
        pid = event['pid']
        tid = event['tid']
        if tid not in self._process_map[pid].threads:
            self._otf2_add_thread(tid, pid, otf2_trace)
            assert tid in self._process_map[pid].threads

        if not event['name'] in self._function_map:
            self._otf2_add_function(event['name'], otf2_trace)

        otf2_thread = self._process_map[pid].threads[tid]
        otf2_function = self._function_map[event['name']]

        if 'dur' in event:
            otf2_thread.leave(self._convert_time_to_ticks(event['ts'] + event['dur']), otf2_function)
        else:
            otf2_thread.enter(self._convert_time_to_ticks(event['ts']), otf2_function)

    def _otf2_add_process(
        self,
        pid: int,
        otf2_trace: otf2.writer.Writer,
        otf2_system_tree_node: otf2.definitions.SystemTreeNode,
        name: str,
    ) -> None:
        process_name = name if name else str(pid)
        otf2_location_group = otf2_trace.definitions.location_group(
            process_name, system_tree_parent=otf2_system_tree_node
        )

        if pid in self._process_map:
            process = self._process_map[pid]
            process.group = otf2_location_group
            process.name = process_name
        else:
            self._process_map[pid] = Process(name=process_name, group=otf2_location_group)

    def _otf2_add_thread(self, tid: int, pid: int, otf2_trace: otf2.writer.Writer, name: Optional[str] = None) -> None:
        process = self._process_map[pid]
        process.threads[tid] = otf2_trace.event_writer(
            name if name else f"{process.name} {tid}",
            group=process.group,
        )

    def _otf2_add_function(self, name: str, otf2_trace: otf2.writer.Writer) -> None:
        otf2_function = otf2_trace.definitions.region(name, paradigm=otf2.Paradigm.USER)
        self._function_map[name] = otf2_function

    # TODO implementation of dataflow
    def _handle_dataflow(self, event: Dict) -> None:
        if event['ph'] == 's':
            if self._dataflow_start is not None:
                print(f"corrupted trace in dataflow: {event}")
                self._dataflow_start = None
            self._dataflow_start = event['id']
            # dataflow handling

        elif event['ph'] == 't':
            if self._dataflow_start != event['id']:
                print(f"corrupted trace in dataflow: {event}")
            # dataflow handling

            self._dataflow_start = None


def cli():
    parser = argparse.ArgumentParser(description="Convert chrome traces into OTF2")
    parser.add_argument(
        "-i",
        "--input",
        type=str,
        required=True,
        help="chrome tracing file",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        required=True,
        help="OTF2 Tracing folder",
    )
    parser.add_argument(
        "-c",
        "--clean",
        action="store_true",
        help="Clean (delete) the output folder if it exists",
    )
    args = parser.parse_args()

    out_folder = args.output
    if args.clean and os.path.exists(out_folder):
        shutil.rmtree(out_folder)

    converter = ChromeTrace2OTF2(args.input)
    converter.convert_trace(out_folder)


if __name__ == '__main__':
    cli()

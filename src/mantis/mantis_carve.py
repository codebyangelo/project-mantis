import logging
import re
from typing import List, Tuple, Iterable

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

# Imports for process listing
from volatility3.plugins.linux import pslist as linux_pslist
from volatility3.plugins.windows import pslist as windows_pslist

vollog = logging.getLogger(__name__)


class MantisLinuxCarve(interfaces.plugins.PluginInterface):
    """Surgically carves memory strings matching a regex from a Linux process."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=linux_pslist.PsList, version=(4, 0, 0)
            ),
            requirements.IntRequirement(
                name="pid",
                description="Process ID to carve",
                optional=False,
            ),
            requirements.StringRequirement(
                name="regex",
                description="Regex pattern to match",
                optional=False,
            ),
        ]

    def _generator(self):
        target_pid = self.config.get("pid")
        regex_pattern = self.config.get("regex")
        try:
            ioc_re = re.compile(regex_pattern, re.IGNORECASE)
        except Exception as e:
            vollog.error(f"Invalid regex: {e}")
            return

        ascii_re = re.compile(rb'[ -~]{8,}')

        # Find the task
        def pid_filter(task):
            return task.tgid == target_pid

        tasks = list(linux_pslist.PsList.list_tasks(
            context=self.context,
            vmlinux_module_name=self.config["kernel"],
            filter_func=pid_filter,
        ))

        if not tasks:
            vollog.warning(f"Process PID {target_pid} not found.")
            return

        for task in tasks:
            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            # Get VMAs
            if not task.mm:
                continue

            for vma in task.mm.get_vma_iter():
                vm_size = vma.vm_end - vma.vm_start
                if vm_size <= 0 or vm_size > 1024 * 1024 * 100:  # Cap size at 100MB per VMA to avoid sanity overflow
                    continue

                try:
                    data = proc_layer.read(vma.vm_start, vm_size, pad=True)
                    if not data:
                        continue
                    for match in ascii_re.findall(data):
                        decoded = match.decode("ascii", errors="ignore")
                        if ioc_re.search(decoded):
                            yield (0, (format_hints.Hex(vma.vm_start), task.tgid, decoded))
                except Exception:
                    pass

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("PID", int),
                ("String", str),
            ],
            self._generator(),
        )


class MantisWindowsCarve(interfaces.plugins.PluginInterface):
    """Surgically carves memory strings matching a regex from a Windows process."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.SymbolTableRequirement(
                name="nt_symbols", description="Windows kernel symbols"
            ),
            requirements.VersionRequirement(
                name="pslist", component=windows_pslist.PsList, version=(2, 0, 0)
            ),
            requirements.IntRequirement(
                name="pid",
                description="Process ID to carve",
                optional=False,
            ),
            requirements.StringRequirement(
                name="regex",
                description="Regex pattern to match",
                optional=False,
            ),
        ]

    def _generator(self):
        target_pid = self.config.get("pid")
        regex_pattern = self.config.get("regex")
        try:
            ioc_re = re.compile(regex_pattern, re.IGNORECASE)
        except Exception as e:
            vollog.error(f"Invalid regex: {e}")
            return

        ascii_re = re.compile(rb'[ -~]{8,}')

        # Find the task
        def pid_filter(proc):
            return proc.UniqueProcessId == target_pid

        procs = list(windows_pslist.PsList.list_processes(
            context=self.context,
            primary_layer_name=self.config["primary"],
            symbol_table_name=self.config["nt_symbols"],
            filter_func=pid_filter,
        ))

        if not procs:
            vollog.warning(f"Process PID {target_pid} not found.")
            return

        for proc in procs:
            proc_layer_name = proc.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            # In Windows, we get the VADs from VadRoot
            for vad in proc.get_vad_root().traverse():
                start = vad.get_start()
                end = vad.get_end()
                size = end - start
                if size <= 0 or size > 1024 * 1024 * 100:
                    continue

                try:
                    data = proc_layer.read(start, size, pad=True)
                    if not data:
                        continue
                    for match in ascii_re.findall(data):
                        decoded = match.decode("ascii", errors="ignore")
                        if ioc_re.search(decoded):
                            yield (0, (format_hints.Hex(start), proc.UniqueProcessId, decoded))
                except Exception:
                    pass

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("PID", int),
                ("String", str),
            ],
            self._generator(),
        )

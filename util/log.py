from typing import TextIO
import sys

class Logger:
	console_log_enabled: bool = None
	file_log_enabled: bool = None
	file: TextIO = None
	current_namespace: str = None
	message: str = None

	def __init__(self, print_to_console=True, file_path=None) -> None:
		self.console_log_enabled = print_to_console

		if file_path != None:
			self.file = open(file_path, "w+")
			self.file_log_enabled = True

	def set_namespace(self, namespace: str) -> None:
		self.current_namespace = namespace

	def _log(self, message: str, file: TextIO, flush: bool):
		log_line = "[ {} ] {}\n".format(self.current_namespace, message)

		if self.file_log_enabled:
			file.write(log_line)
			if flush:
				file.flush()

	def info(self, message: str, flush: bool = True):
		if self.file_log_enabled:
			self._log(message, self.file, flush)

		if self.console_log_enabled:
			self._log(message, sys.stdout, flush)

	def error(self, message: str, flush: bool = True):
		if self.file_log_enabled:
			self._log(message, self.file, flush)

		if self.console_log_enabled:
			self._log(message, sys.stderr, flush)

		self.message = message

	def get_exception_from_last_msg(self) -> Exception:
		return Exception(self.message)

	def __del__(self) -> None:
		if self.file != None and not self.file.closed:
			self.file.close()
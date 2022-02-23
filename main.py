from util.cdndatgenerator import CDNDatGenerator
from sys import argv
import traceback

try:
	datgen = CDNDatGenerator(argv[1])
	datgen.set_dump_tool("[DUMP TOOL]")
	datgen.set_languages(["[LANGUAGES]"])
	datgen.set_region("[REGION]")
	datgen.set_title_name("[TITLE NAME]")
	datgen.set_title_name_alt("[ALT TITLE NAME]")
	datgen.set_dumper("[DUMPER]")
	datgen.create_game()
except Exception as e:
	print("ERROR:")
	traceback.print_exception(Exception, e, e.__traceback__)
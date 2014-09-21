import sys, os, importlib, logging

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class PatternFactory( object ):
	"""Factory for creating on fly set rules for desired class"""
	def __str__( self ):
		return ("Pattern factory")

	def New ( self, msg, label, score):
		print(label)
		try:

			pattern = importlib.import_module(label+'_pattern')

			#logger.debug ((check.title()).replace('_',''))

			current_test_obj=getattr(pattern, (label.title()+'Pattern'))

		except Exception, details:
			raise

		return (current_test_obj(msg))

MetaPattern = PatternFactory()

.PHONY: test
test: ../../src/bulk_extractor.so
	python3 modbulk_extractor.py

../../src/bulk_extractor.so:
	cd ../../src; make bulk_extractor.so

all: doc
	chmod +x springbok.py test/test.py

doc:
	cd documentation; \
	pwd; \
	rm -r latex/ html/; \
	doxygen short_doc; \
	cd latex; \
	make pdf; \
	cp refman.pdf ../springbok_short_documentation.pdf; \
	cd ../; \
	rm -r latex/ html/; \
	doxygen long_doc; \
	cd latex; \
	make pdf; \
	cp refman.pdf ../springbok_documentation.pdf; \
	cd ../; \
	cd ../; \

test:
	cd test; \
	./test.py; \
	cd ../; \

clean:
	cd documentation; \
	rm -r latex/ html/ springbok_documentation.pdf springbok_short_documentation.pdf; \
	cd ../; \
	find . -name "*.pyc" -exec rm -rf {} \;; \
	find . -name "parser.out" -exec rm -rf {} \;; \
	find . -name "parsetab.py" -exec rm -rf {} \;; \
	find . -name "lextab.py" -exec rm -rf {} \;; \
	find . -name "*~" -exec rm -rf {} \;; \

.PHONY: all test doc clean
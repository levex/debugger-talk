talk.pdf: talk.tex
	latexmk -pdf $<

clean:
	rm $(shell find . -name 'talk.*' | egrep -v 'talk\.tex')

.PHONY: clean

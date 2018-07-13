venv: requirements.txt
	rm -rf $@
	virtualenv -ppython3.6 $@
	$@/bin/pip install -r $^

.PHONY: start-dev
start-dev: venv
	venv/bin/gunicorn -b 0.0.0.0:5000 fuzzy:app

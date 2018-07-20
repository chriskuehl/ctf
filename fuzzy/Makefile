venv: requirements.txt
	rm -rf $@
	virtualenv -ppython3.6 $@
	$@/bin/pip install -r $^

.PHONY: start-dev
start-dev: venv
	venv/bin/gunicorn -b 0.0.0.0:4999 fuzzy:app

.PHONY: start-prod
start-prod: venv
	venv/bin/gunicorn -w16 -b 127.0.0.1:5000 fuzzy:app

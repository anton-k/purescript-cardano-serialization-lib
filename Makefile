.PHONY: build test run watch serve format check-format

esbuild-cmd := "esbuild \
			./output/Main/index.js \
			--bundle \
			--outfile=demo/src/purs.js \
			--platform=browser \
			--format=esm \
			--external:@emurgo/cardano-serialization-lib-browser"

build:
	spago build 

test:
	echo "TODO: implement purs tests"

run:
	spago build --then ${esbuild-cmd}

watch:
	spago build --then ${esbuild-cmd} --watch

serve: run
	(cd demo && npm run build && npm run serve)
	
format:
	purs-tidy format-in-place "src/**/*.purs"

check-format:
	purs-tidy check "src/**/*.purs"


.PHONY: build test vet clean run update-deps

build:
	go build -o localCA .

test:
	go test -v -timeout 180s ./...

vet:
	go vet ./...

clean:
	rm -f localCA

run: build
	./localCA -port 8080 ./ca

update-deps:
	@mkdir -p ui/fonts
	@rm -f ui/fonts/*.woff2 ui/fonts/inter.css
	@echo "Fetching Inter font CSS from Google Fonts..."
	@ua='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'; \
	url='https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap'; \
	curl -s -H "User-Agent: $$ua" "$$url" > ui/fonts/inter.css
	@echo "Downloading font files..."
	@ua='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'; \
	grep -oP 'https?://[^)]+' ui/fonts/inter.css | sort -u | while read f_url; do \
	  file=$$(basename "$$f_url"); \
	  echo "  $$file"; \
	  curl -sL -H "User-Agent: $$ua" "$$f_url" -o "ui/fonts/$$file"; \
	  sed -i "s|$$f_url|/static/fonts/$$file|g" ui/fonts/inter.css; \
	done; \
	echo "Done. Font files in ui/fonts/"

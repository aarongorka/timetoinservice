ifdef GO_PIPELINE_LABEL
	BUILD_VERSION?=$(GO_PIPELINE_LABEL)
else
	BUILD_VERSION?=local
endif
ifdef AWS_ROLE
	ASSUME_REQUIRED?=assumeRole
endif
ifdef DOTENV
	DOTENV_TARGET=dotenv
else
	DOTENV_TARGET=.env
endif

VERSION = 0.0.7
IMAGE_NAME ?= aarongorka/timetoinservice

dockerBuild:
	docker build -t $(IMAGE_NAME):$(VERSION) .
	docker build -t $(IMAGE_NAME):latest .

ecrLogin:
	$(shell aws ecr get-login --no-include-email --region ap-southeast-2)

dockerPush:
	docker push $(IMAGE_NAME):$(VERSION)
	docker push $(IMAGE_NAME):latest

gitTag:
	git tag $(VERSION)
	git push origin $(VERSION)

deploy: $(DOTENV_TARGET) $(ASSUME_REQUIRED)
	docker-compose down
	docker-compose run --rm ecs make -f /scripts/Makefile deploy
	docker-compose down

cutover: $(DOTENV_TARGET) $(ASSUME_REQUIRED)
	docker-compose down
	docker-compose run --rm ecs make -f /scripts/Makefile cutover
	docker-compose down

cleanup: $(DOTENV_TARGET) $(ASSUME_REQUIRED)
	docker-compose down
	docker-compose run --rm ecs make -f /scripts/Makefile cleanup
	docker-compose down

.env:
	@echo "Create .env with .env.template"
	cp .env.template .env
	echo "" >> .env
	echo "BUILD_VERSION=$(BUILD_VERSION)" >> .env
	echo "VERSION=$(VERSION)" >> .env

# Create/Overwrite .env with $(DOTENV)
dotenv:
	@echo "Overwrite .env with $(DOTENV)"
	cp $(DOTENV) .env
	echo "BUILD_VERSION=$(BUILD_VERSION)" >> .env

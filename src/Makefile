#@BEGIN-SRC-DEFAULT-RULES@
DEPSDIR=.deps
ERLC=$(shell which erlc)
ERLC_FLAGS=-MMD -MF $(DEPSDIR)/$<.d -I ../.. +debug_info -Ddebug
#ERL_HEADERS=$(wildcard *.hrl) $(wildcard ../../*/include/*.hrl)
ERL_SOURCES=$(wildcard *.erl)
ERL_OBJECTS=$(ERL_SOURCES:%.erl=../ebin/%.beam)
ALL_OBJECTS=$(ERL_OBJECTS)

.PHONY: directories

all: directories $(ALL_OBJECTS)

directories:	$(DEPSDIR)

$(DEPSDIR):
	mkdir -p $(DEPSDIR)

clean:
	rm -f $(ALL_OBJECTS) *.core $(DEPSDIR)/*.d

../ebin/%.beam: %.erl
	$(ERLC) $(ERLC_FLAGS) -o ../ebin $<

-include $(DEPSDIR)/*.d
#@END-SRC-DEFAULT-RULES@

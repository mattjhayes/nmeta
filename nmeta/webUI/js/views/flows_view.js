nmeta.FlowsView = Backbone.View.extend({

    initialize:function (options) {
        // Get options passed to us:
        this.options = options || {};

        // We're passed a model to hold UI states in for random stuff:
        this.flowsState = this.options.flowsState;
        this.flowsState.set('filterString', '');

        // Bind 'reset' event to run render function on this collection:
        this.model.on("reset", this.render, this);

        // Bind flow 'add' event to create new instance of FlowView
        // and render it against id='flow' (table row):
        this.model.on("add", function (flow) {
          console.log('FlowsView add called');
            $('#flow', this.el).append(new nmeta.FlowView({model:flow}).render().el);
        });
    },

    events: {
        // Bind flowsFilterLogicSelector to function:
        'change #flowsFilterLogicSelector' : 'flowsFilterLogicSelector',

        // Bind flowsFilterTypeSelector to function:
        'change #flowsFilterTypeSelector' : 'flowsFilterTypeSelector',

        // Bind flowsFilterText to function:
        'keyup #flowsFilterText' : 'flowsFilterTextProcessKey',

        // Bind clearFlowsFilter click to function:
        'click .clearFlowsFilter': 'clearFlowsFilter',

        // Bind refreshFlows click to function:
        'click .refreshFlows': 'refreshFlows'
    },

    flowsFilterLogicSelector:function () {
        // Store state of flowsFilterLogicSelector:
        this.flowsState.set('flowsFilterLogicSelector', $("#flowsFilterLogicSelector").val());
    },

    flowsFilterTypeSelector:function () {
        // Store state of flowsFilterTypeSelector:
        this.flowsState.set('flowsFilterTypeSelector', $("#flowsFilterTypeSelector").val());
    },

    clearFlowsFilter:function () {
        // Clear all filtering and re-render view
        console.log('in clearFlowsFilter, clearing ', this.flowsState.get('filterString'));
        // Set drop-down select menus to default state:
        this.flowsState.set('flowsFilterLogicSelector', 'includes');
        this.flowsState.set('flowsFilterTypeSelector', 'any');
        // Clear filter string:
        this.flowsState.set('filterString', '');
        $("#flowsFilterText").val('');
        // Retrieve fresh data without filterString and re-render view:
        this.model.fetch({reset: true,
                            data: $.param({
                                flowsFilterLogicSelector: this.flowsState.get('flowsFilterLogicSelector'),
                                flowsFilterTypeSelector: this.flowsState.get('flowsFilterTypeSelector'),
                                filterString: this.flowsState.get('filterString')
                                })
                            })

    },

    refreshFlows:function () {
        // Fetch flows_collection, sending as reset event:
        console.log('FlowsView refreshFlows calling fetch() as reset and search=', this.flowsState.get('filterString'));
        this.model.fetch({reset: true,
                            data: $.param({
                                flowsFilterLogicSelector: this.flowsState.get('flowsFilterLogicSelector'),
                                flowsFilterTypeSelector: this.flowsState.get('flowsFilterTypeSelector'),
                                filterString: this.flowsState.get('filterString')
                                })
                            })
    },

    render:function () {
        console.log('FlowsView render function');

        // Start with empty el:
        this.$el.empty();

        // Apply FlowsView.html template:
        this.$el.html(this.template());

        // Render flow models:
        var self = this;
        // Iterate through models in collection:
        _.each(this.model.models, function (flow) {
            // Instantiate flow view for model:
            var flowView = new nmeta.FlowView({ model : flow });
            // Append rendered flow view to el id="flow":
            $('#flow', this.el).append(flowView.render().el);
        });

        // Re-select flowsFilterLogicSelector setting:
        $("#flowsFilterLogicSelector option[value='" + this.flowsState.get('flowsFilterLogicSelector') + "']").attr("selected", "selected");

        // Re-select flowsFilterTypeSelector setting:
        $("#flowsFilterTypeSelector option[value='" + this.flowsState.get('flowsFilterTypeSelector') + "']").attr("selected", "selected");

        // Re-add value to user text input:
        $('#flowsFilterText').val(this.flowsState.get('filterString'));

        return this;
    },

    flowsFilterTextProcessKey: function(e) {
        // Only perform flow search if form is submitted:
        if(e.which === 13) // enter key
        this.search();
    },

    search : function(e){
        console.log('FlowsView search function');

        // Get search term:
        var searchTerm = $("#flowsFilterText").val();
        console.log('FlowsView search function, searchTerm=', searchTerm);

        // Store search term:
        this.flowsState.set('filterString', searchTerm);

        console.log('#flowsFilterLogicSelector=', $("#flowsFilterLogicSelector").val());

        this.model.fetch({reset: true,
                            data: $.param({
                                flowsFilterLogicSelector: this.flowsState.get('flowsFilterLogicSelector'),
                                flowsFilterTypeSelector: this.flowsState.get('flowsFilterTypeSelector'),
                                filterString: this.flowsState.get('filterString')
                                })
                            })
    }

});

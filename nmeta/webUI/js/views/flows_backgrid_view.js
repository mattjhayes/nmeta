nmeta.FlowsBackGridView = Backbone.View.extend({

    initialize:function (options) {
        // Specify columns that will be displayed in Backgrid:
        var columns = [{
            name: "timestamp", 
            label: "Timestamp",
            editable: false,
            // Extend UriCell to have timestamp custom link to flow_hash value:
            cell: Backgrid.UriCell.extend({
                render: function () {
                    this.$el.empty();
                    var formattedValue = this.formatter.fromRaw(this.model.get('timestamp'), this.model);
                    this.$el.append($("<a>", {
                        href: "#flowDetails/" + this.model.get('flow_hash'),
                        title: 'click for flow details'
                    }).text(formattedValue));
                    this.delegateEvents();
                    return this;
                }
            }),
          }, {
            name: "src_location_logical",
            label: "Src Location",
            editable: false,
            cell: "string"
          }, {
            name: "src",
            label: "Src",
            editable: false,
            cell: "string"
          }, {
            name: "dst",
            label: "Dst",
            editable: false,
            cell: "string"
          }, {
            name: "proto",
            label: "Proto",
            editable: false,
            cell: "string"
          }, {
            name: "tp_src",
            label: "TP Src",
            editable: false,
            cell: "string"
          }, {
            name: "tp_dst",
            label: "TP Dst",
            editable: false,
            cell: "string"
          }, {
            name: "classification",
            label: "Classification",
            editable: false,
            cell: "string"
          }, {
            name: "actions",
            label: "Actions",
            editable: false,
            cell: "string"
          }, {
            name: "data_sent",
            label: "Sent",
            editable: false,
            cell: "string"
          }, {
            name: "data_received",
            label: "Received",
            editable: false,
            cell: "string"
          }];
        // Set up a Backgrid grid to use the pageable collection
        this.pageableGrid = new Backgrid.Grid({
          columns: columns,
          collection: this.model
        });


        // Display a loading indication whenever the Collection is fetching.
        this.model.on("request", function() {
            this.$el.html("Loading...");
        }, this);

        this.model.on('reset', this.render, this);
        this.model.on('change', this.render, this);

    },

    render:function () {
        console.log('FlowsBackgridView render function');

        // Start with empty el:
        this.$el.empty();

        // Render the grid:
        this.$el.append(this.pageableGrid.render().el)

        return this;
    },

});

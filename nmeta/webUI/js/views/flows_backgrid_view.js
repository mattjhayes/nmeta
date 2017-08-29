nmeta.FlowsBackGridView = Backbone.View.extend({

    initialize:function (options) {
        var columns = [{
            name: "timestamp", 
            label: "Timestamp",
            editable: false,
            cell: "string"
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
        // Set up a grid to use the pageable collection
        this.pageableGrid = new Backgrid.Grid({
          //columns: [{
            // enable the select-all extension
            //name: "",
            //cell: "select-row",
            //headerCell: "select-all"
          //}].concat(columns),
          columns: columns,
          collection: this.model
        });

        // Initialise the paginator
        this.paginator = new Backgrid.Extension.Paginator({
            collection: this.model
        });

        // Initialise a client-side filter to filter on the client
        // mode pageable collection's cache:
        this.filter = new Backgrid.Extension.ClientSideFilter({
            collection: this.model,
            fields: ['src_location_logical', 'src', 'dst']
        });

        this.model.on("reset", this.render, this);
        this.model.on('change', this.render, this);

    },

    render:function () {
        console.log('FlowsBackgridView render function');

        // Start with empty el:
        this.$el.empty();

        // Apply FlowsView.html template:
        // this.$el.html(this.template());

        // Render the grid:
        this.$el.append(this.pageableGrid.render().el)

        // Render the paginator:
        this.$el.after(this.paginator.render().el);

        // Render the filter
        this.$el.before(this.filter.render().el);

        return this;
    },

});

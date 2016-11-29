(function ($) {
    //-------- Models:
    var PacketIn = Backbone.Model.extend({
        defaults:{
            packetinImage:"img/packet_in.png",
            pi_rate: "pi rate default"
        },
        parse:function (response) {
            console.log(response);
            response.id = response._id;
            return response;
        }
    });

    //-------- Model of multiple PacketIn models:
    var PacketIns = Backbone.Collection.extend({
        model:PacketIn,
        url:'/v1/infrastructure/controllers/pi_rate',
    });

    //-------- Views:
    var PacketInView = Backbone.View.extend({
        tagName:"div",
        className:"packetinContainer",
        template:$("#packetinTemplate").html(),

        render:function () {
            var tmpl = _.template(this.template);

            this.$el.html(tmpl(this.model.toJSON()));
            return this;
        }
    });

    //-------- View of multiple PacketIns:
    var PacketInsView = Backbone.View.extend({
        el:$("#packetins"),

        initialize: function(){
          this.collection = new PacketIns();
            this.collection.fetch({
                error:function () {
                    console.log(arguments);
                }
            });
          this.render();

          this.collection.on("add", this.renderPacketIn, this);
        },

        render:function () {
            var that = this;
            _.each(this.collection.models, function (item) {
                that.renderPacketIn(item);
            });
        },

        renderPacketIn:function(item){
            var packetinView = new PacketInView({
                model: item
            });
            this.$el.append(packetinView.render().el);
        }
    });

    var packetinsView = new PacketInsView();


})(jQuery);

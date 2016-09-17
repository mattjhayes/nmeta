#########
API Guide
#########

The nmeta API provides HTTP read access (no write at this stage) to data
within nmeta. Data includes:

  Conversation Type Metadata
    The types of conversations that are occuring over the network
  Participant Metadata
    Who and what is connected to the network
  Performance Metrics
    How the system is performing

Here is a visualisation of the API hierarchy:

.. image:: images/api_hierarchy.png

To return the JSON in a human-friendly format, precede the API call with the <a href="misc.html#jsonpretty.py" target="_blank">jsonpretty.py</a> script
  (requires install of <a href="misc.html#jsonpretty.py" target="_blank">simplejson</a>):
</p>
<pre><code>sudo python ~/nmeta/misc/jsonpretty.py API_CALL_HERE
</code></pre>

<p>Example API Calls to run on local host (jsonpretty.py omitted for brevity):</p>

<h3>
<a id="conversation-type-metadata-api" class="anchor" href="#conversation-type-metadata-api" aria-hidden="true"><span class="octicon octicon-link"></span></a>Conversation Type Metadata API Calls
</h3>

<p>Return the Flow Metadata Table:</p>

<pre><code>http://127.0.0.1:8080/nmeta/flowtable/
</code></pre>
<p>
  Returns the whole flow table - use with caution due to load considerations
</p>

<h3>
<a id="participant-metadata-api" class="anchor" href="#participant-metadata-api" aria-hidden="true"><span class="octicon octicon-link"></span></a>Participant Metadata API Calls
</h3>

<p>Return the Identity MAC structure:</p>

<pre><code>http://127.0.0.1:8080/nmeta/identity/mac/
</code></pre>

<p>Return the Identity IP structure:</p>

<pre><code>http://127.0.0.1:8080/nmeta/identity/ip/
</code></pre>

<p>Return the Identity Service structure:</p>

<pre><code>http://127.0.0.1:8080/nmeta/identity/service/
</code></pre>

<p>Return the Identity NIC Table (old - will be deprecated at some stage):</p>

<pre><code>http://127.0.0.1:8080/nmeta/identity/nictable/
</code></pre>

<p>Return the Identity System Table (old - will be deprecated at some stage):</p>

<pre><code>http://127.0.0.1:8080/nmeta/identity/systemtable/
</code></pre>

<h3>
<a id="performance-metric-api" class="anchor" href="#performance-metric-api" aria-hidden="true"><span class="octicon octicon-link"></span></a>Performance Metric API Calls
</h3>

<p>Return the Flow Metadata table size as number of rows:</p>

<pre>http://127.0.0.1:8080/nmeta/measurement/tablesize/rows/
</code></pre>

<p>Return the rate at which nmeta is processing events from switches, as events per second:</p>

<pre><code>http://127.0.0.1:8080/nmeta/measurement/eventrates/
</code></pre>

<p>Return statistics on nmeta per-packet processing time:</p>

<pre><code>http://127.0.0.1:8080/nmeta/measurement/metrics/packet_time/
</code></pre>


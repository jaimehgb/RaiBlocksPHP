# RaiBlocksPHP
A bunch of PHP methods to build and sign transactions

<h3>Overview</h3>
<p>
So yeah, some more tools for people building stuff around RaiBlocks :)<br/>
This basically allows you to build transactions and sign them directly from your application, without the need of interacting with 
RaiBlocks node. You'll need to broadcast them though, and you may need a node to do that, but hey :D
</p>

<h3>Usage</h3>
<p>
<pre>git clone ...</pre>
You can see some examples at the Tests folder. I may put some more here at the README in the future, when I have a minute :P
</p>

<h3>Dependencies</h3>
<p>
This library depends on a modified version of <a href="https://github.com/devi/Salt">Salt</a>, a NaCl library for PHP. The modification basically
consists on a change on the hash function used at the cryto_sign methods. You can find it <a href="https://github.com/jaimehgb/Salt">here</a>.
It's already included in this repo.
</p>

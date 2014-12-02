var myLayout;

$(document).ready( function() {
  // create tabs FIRST so elems are correct size BEFORE Layout measures them
  $("#main_panel").tabs({
    activate: function( event, ui ) {
      r2ui.seek("$$", false);
      scroll_to_element(r2ui._dis.selected);
      document.getElementById("canvas").focus();
    }
  });

	// Layout
	myLayout = $('body').layout({
		west__size:			200,
		east__size:			200,
    south__size:    200,
    north__resizable: false,
		west__onresize:		$.layout.callbacks.resizePaneAccordions,
		east__onresize:		$.layout.callbacks.resizePaneAccordions
	});
  myLayout.disableClosable("north", true);
	$("#accordion1").accordion({ heightStyle:  "fill" });
	$("#accordion2").accordion({ heightStyle:  "fill" });

  // Boot r2 analysis, settings, ....
	r2.update_flags();
	r2.analAll();
	r2.load_mmap();
	r2ui.load_colors();
	r2.load_settings();
  update_binary_details();

  // Create panels
	var disasm_panel = new DisasmPanel();
	var hex_panel = new HexPanel();
	r2ui._dis = disasm_panel;
	r2ui._hex = hex_panel;

  // For enyo compatibility
	r2ui.ra = {};
  r2ui.mp = {};
	r2ui.ra.getIndex = function() {};
	r2ui.ra.setIndex = function() {};
	r2ui.mp.openPage = function() {};

  var console_history = [];
  var console_history_idx = 0;

  // Handle commands in console
  $("#command").keypress(function( inEvent ) {
    var key = inEvent.keyCode || inEvent.charCode || inEvent.which || 0;
    if (key === 13) {
      var cmd = inEvent.target.value.trim();
      console_history[console_history.length] = cmd;
      console_history_idx += 1;
      r2.cmd(cmd, function(x) {
        var old_value = $("#cmd_output").text();
        $("#cmd_output").html(old_value + "\n> " + cmd + "\n" + x );
        $('#cmd_output').scrollTo($('#cmd_output')[0].scrollHeight);

      });
      if (cmd.indexOf("s ") === 0) {
        r2ui.history_push(r2ui._dis.selected_offset);
      }
      r2.load_settings();
      r2ui.load_colors();
      update_binary_details();
      inEvent.target.value = "";
      r2ui.seek("$$", false);
      scroll_to_element(r2ui._dis.selected);
    }
  });
  $("#command").keydown(function( inEvent ) {
    var key = inEvent.keyCode || inEvent.charCode || inEvent.which || 0;
    if (key === 40) {
      console_history_idx++;
      if (console_history_idx > console_history.length - 1) console_history_idx = console_history.length;
      inEvent.target.value = console_history[console_history_idx] === undefined ? "" : console_history[console_history_idx];
    }
    if (key === 38) {
      console_history_idx--;
      if (console_history_idx < 0) console_history_idx = 0;
      inEvent.target.value = console_history[console_history_idx] === undefined ? "" : console_history[console_history_idx];
    }
  });

  // Context menu for addresses:
  $(document).contextmenu({
      delegate: ".addr",
      menu: [
          {title: "jump to address<kbd>g</kbd>", cmd: "goto"},
          {title: "rename<kbd>n</kbd>", cmd: "rename"},
          {title: "add comment<kbd>;</kbd>", cmd: "comment"},
          {title: "code<kbd>c</kbd>", cmd: "define"},
          {title: "undefine<kbd>u</kbd>", cmd: "undefine"}
      ],
      preventSelect: true,
      preventContextMenuForPopup: true,
      show: false,
      position: function(event, ui){
        return {my: "left+100 top-10", at: "left bottom", of: ui.target};
      },
      beforeOpen: function(event, ui) {
        var target = ui.target[0];
        if (target.className.indexOf("insaddr") !== 0) {
          $(document).contextmenu("showEntry", "define", false);
          $(document).contextmenu("showEntry", "undefine", false);
        }
      },
      select: function(event, ui) {
        $(document).contextmenu("close");
        var target = ui.target[0];
        var address = get_address_from_class(target);
        if (ui.cmd  == "goto") do_goto();
        if (ui.cmd  == "comment") do_comment(target);
        if (ui.cmd  == "rename") do_rename(target, event);
        if (ui.cmd  == "define") do_define(target);
        if (ui.cmd  == "undefine") do_undefine(target);
      }
  });

  // Install keyboard and mosuse handlers
  $("#main_panel").keypress(handleKeypress);
  $("#main_panel").click(handleClick);
  $(document).dblclick(handleDoubleClick);

  // Show disasm panel and seek to entrypoint
	disasm_panel.display_flat();
	r2ui.seek(disasm_panel.base,true);
	scroll_to_element(r2ui._dis.selected);
  document.getElementById("canvas").focus();

});

function scroll_to_element(element) {
  var top = Math.max(0,element.documentOffsetTop() - ( window.innerHeight / 2 ));
  $('#center_panel').scrollTo(top, {axis: 'y'});
}

function scroll_to_address(address) {
  var elements = document.getElementsByClassName("insaddr addr_" + address);
  if (elements.length == 1) {
    var top = elements[0].documentOffsetTop() - ( window.innerHeight / 2 );
    top = Math.max(0,top);
    $('#center_panel').scrollTo(top, {axis: 'y'});
  }
}

function rehighlight_iaddress(address) {
  $('.autohighlighti').removeClass('autohighlighti');
  $('.addr_' + address).addClass('autohighlighti');
}

function getOffsetRect(elem) {
    var box = elem.getBoundingClientRect();
    var offset = $('#gbox').offset().top;
    var top  = box.top - offset;
    var bottom  = box.bottom - offset;
    return {top: Math.round(top), bottom: Math.round(bottom)};
}

// key handler
function handleKeypress(inEvent) {
	var key = inEvent.keyCode || inEvent.charCode || inEvent.which || 0;

  // console.log(key);

	// show help
	if (key === 63) {
	  // r2ui.mp.showPopup();
	}
  if (r2ui._dis.renaming !== null) return;

	// Spacebar Switch flat and graph views
	if (key === 32) {
    var address = get_address_from_class(r2ui._dis.selected);
    if (address !== undefined && address !== null) {
      if (r2ui._dis.display === "flat") r2ui._dis.display_graph();
      else if (r2ui._dis.display === "graph") r2ui._dis.display_flat();
      r2ui.seek(address, true);
      scroll_to_address(address);
      inEvent.preventDefault();
      document.getElementById("canvas").focus();
    }
	}
	// h Seek to previous address in history
	if (key === 104) do_jumpto(r2ui.history_prev());

	// l Seek to next address in history
	if (key === 108) do_jumpto(r2ui.history_next());

	// j Seek to next Instruction
	if (key === 106) {
    var get_more_instructions = false;
    if ($(r2ui._dis.selected).hasClass("insaddr")) {
      var next_instruction;
      if (r2ui._dis.display == "flat") {
        next_instruction = $(r2ui._dis.selected).closest(".instructionbox").next().find('.insaddr')[0];
        if ($("#gbox .instructionbox").index( $(r2ui._dis.selected).closest(".instructionbox")[0]) > $("#gbox .instructionbox").length - 10) get_more_instructions = true;
      }
      if (r2ui._dis.display == "graph") {
        var next_instruction = $(r2ui._dis.selected).closest(".instruction").next().find('.insaddr')[0];
        if (next_instruction === undefined || next_instruction === null) {
          next_instruction = $(r2ui._dis.selected).closest(".basicblock").next().find('.insaddr')[0];
        }
      }

      // if (next_instruction === null || next_instruction === undefined) return;
      var address = get_address_from_class(next_instruction);
      if (get_more_instructions) {
        r2ui.seek(address, false);
      } else {
        r2ui.history_push(address);
        render_history();
        r2ui._dis.selected = next_instruction;
        r2ui._dis.selected_offset = address;
      }
      rehighlight_iaddress(address);
      scroll_to_address(address);
      document.getElementById("canvas").focus();
    }
	}
	// k Seek to previous instruction
	if (key === 107) {
    var get_more_instructions = false;
    if ($(r2ui._dis.selected).hasClass("insaddr")) {
      var prev_instruction;
      if (r2ui._dis.display == "flat") {
        prev_instruction = $(r2ui._dis.selected).closest(".instructionbox").prev().find('.insaddr')[0];
        if ($("#gbox .instructionbox").index( $(r2ui._dis.selected).closest(".instructionbox")[0]) < 10) get_more_instructions = true;
      }
      if (r2ui._dis.display == "graph") {
        var prev_instruction = $(r2ui._dis.selected).closest(".instruction").prev().find('.insaddr')[0];
        if (prev_instruction === undefined || prev_instruction === null) {
          prev_instruction = $(r2ui._dis.selected).closest(".basicblock").prev().find('.insaddr').last()[0];
        }
      }
      var address = get_address_from_class(prev_instruction);
      if (get_more_instructions) {
        r2ui.seek(address, false);
      } else {
        r2ui.history_push(address);
        render_history();
        r2ui._dis.selected = prev_instruction;
        r2ui._dis.selected_offset = address;
      }
      rehighlight_iaddress(address);
      scroll_to_address(address);
      document.getElementById("canvas").focus();
    }
	}
	// c Define function
	if (key === 99) do_define(r2ui._dis.selected);

	// u Clear function metadata
	if (key === 117) do_undefine(r2ui._dis.selected);

	// g Go to address
	if (key === 103) do_goto();

	// ; Add comment
	if (key === 59) do_comment(r2ui._dis.selected);

	// n Rename
	if (key === 110) do_rename(r2ui._dis.selected, inEvent);

	// esc
	if (key === 27) {
	  // Esc belongs to renaming
	  if(r2ui._dis.renaming !== null) {
	    r2ui._dis.renaming.innerHTML = r2ui._dis.renameOldValue;
	    r2ui._dis.renaming = null;
	  } else {
	    // go back in history
	    var addr = r2ui.history_prev();
	    if (addr !== undefined && addr !== null) r2ui.seek(addr, false);
	    scroll_to_address(addr);
	  }
    document.getElementById("canvas").focus();
	}
	// enter
	if (key === 13) {
	  // Enter go to address
	  r2ui._dis.goToAddress();
    document.getElementById("canvas").focus();
	}
}

function do_jumpto(address) {

  var element = $('.insaddr.addr_' + address);
  if (element.length > 0) {
    r2ui.history_push(address);
    render_history();
    r2ui._dis.selected = element;
    r2ui._dis.selected_offset = address;
  } else {
    r2ui.seek(address, true);
  }
  rehighlight_iaddress(address);
  scroll_to_address(address);
  document.getElementById("canvas").focus();
}

function do_goto() {
  r2ui.opendis(prompt('Go to'));
  scroll_to_element(r2ui._dis.selected);
  document.getElementById("canvas").focus();
}

function do_rename(element, inEvent) {
  if (r2ui._dis.renaming === null && element !== null && (element.className.indexOf(" addr ") ) -1) {
    var address = get_address_from_class(element);
    r2ui._dis.selected = element;
    r2ui._dis.selected_offset = address;
    r2ui._dis.renaming = element;
    r2ui._dis.renameOldValue = element.innerHTML;
    r2ui._dis.rbox = document.createElement('input');
    r2ui._dis.rbox.setAttribute("type", "text");
    r2ui._dis.rbox.setAttribute("id", "rename");
    r2ui._dis.rbox.setAttribute("style", "border-width: 0;padding: 0;");
    r2ui._dis.rbox.setAttribute("onChange", "handleInputTextChange()");
    r2ui._dis.rbox.setAttribute("value", "");
    r2ui._dis.renaming.innerHTML = "";
    r2ui._dis.renaming.appendChild(r2ui._dis.rbox);
    setTimeout('r2ui._dis.rbox.focus();', 200);
    inEvent.returnValue=false;
    inEvent.preventDefault();
    update_binary_details();
  }
}

function do_comment(element) {
  var address = get_address_from_class(element);
  r2.cmd('CC ' + prompt('Comment')  + " @ " + address);
  r2ui.seek(address, false);
  scroll_to_address(address);
  document.getElementById("canvas").focus();
}

function do_undefine(element) {
  var address = get_address_from_class(element);
  r2.cmd("af-");
  r2.update_flags();
  update_binary_details();
  if (r2ui._dis.display == "graph") r2ui._dis.display_flat();
  r2ui.seek(address, false);
  scroll_to_address(address);
  document.getElementById("canvas").focus();
}

function do_define(element) {
  var address = get_address_from_class(element);
  var msg = prompt ('Function name?');
  r2.cmd("af " + msg + " @ " + address);
  r2.update_flags();
  update_binary_details();
  r2ui.seek(address, false);
  scroll_to_address(address);
  document.getElementById("canvas").focus();
}

function handleClick(inEvent) {
  if ($(inEvent.target).hasClass('addr')) {
    var address = get_address_from_class(inEvent.target);
    r2ui._dis.selected = inEvent.target;
    r2ui._dis.selected_offset = address;
    rehighlight_iaddress(address);
    // If instruction address, add address to history
    if ($(inEvent.target).hasClass('insaddr')) {
      r2ui.history_push(address);
      render_history();
    }
  }
  document.getElementById("canvas").focus();
}

function handleDoubleClick (inEvent) {
  if ($(inEvent.target).hasClass('addr') && !$(inEvent.target).hasClass('insaddr')) {
    handleClick(inEvent);
    r2ui._dis.goToAddress();
    inEvent.preventDefault();
  }
  document.getElementById("canvas").focus();
}


// METHOD to UPDATE all LATERAL Information
function update_binary_details() {

  // <div id="symbols"></div>
  r2.cmdj("isj", function(x) {
    render_symbols(x);
  });
  // <div id="strings"></div>
  r2.cmdj("izj", function(x) {
    render_strings(x);
  });
  // <div id="functions"></div>
  // <div id="imports"></div>
  r2.cmdj("afj", function(x) {
    render_functions(x);
  });
  // <div id="relocs"></div>
  r2.cmdj("irj", function(x) {
    render_relocs(x);
  });
  // <div id="flags"></div>
  r2.cmdj("fs *;fj", function(x) {
    render_flags(x);
  });
  // <div id="information"></div>
  r2.cmd("i", function(x) {
    $('#information').html("<pre>" + x + "</pre>");
  });
  // <div id="sections"></div>
  r2.cmdj("iSj", function(x) {
    render_sections(x);
  });
  render_history();
}


function render_functions(functions) {
  var fcn_data = [];
  var imp_data = [];
  for (var i in functions) {
    var f = functions[i];
    if (f.type == "sym") {
      var id = {
        label: "<span class='function addr addr_" + "0x" + f.offset.toString(16) + "'>" + f.name + "</span>",
        children: [ {label: "offset: " + "0x" + f.offset.toString(16)}, {label: "size: " + f.size} ] };
      if (f.callrefs.length > 0) {
        var xrefs = {label: "xrefs:", children: []};
        for (var j in f.callrefs) {
          xrefs.children[xrefs.children.length] = "0x" + f.callrefs[j].addr.toString(16) + " (" + (f.callrefs[j].type == "C"? "call":"jump") + ")";
        }
        id.children[fd.children.length] = xrefs;
      }
      imp_data[fcn_data.length] = id;
    }
    if (f.type == "fcn") {
      var fd = {
        label: "<span class='function addr addr_" + "0x" + f.offset.toString(16) + "'>" + f.name + "</span>",
        children: [{label: "offset: " + "0x" + f.offset.toString(16)},  {label: "size: " + f.size} ] };
      if (f.callrefs.length > 0) {
        var xrefs = {label: "xrefs:", children: []};
        for (var j in f.callrefs) {
          xrefs.children[xrefs.children.length] = "<span class='xref addr addr_0x" + f.callrefs[j].addr.toString(16)  + "'>0x" + f.callrefs[j].addr.toString(16) + "</span> (" + (f.callrefs[j].type == "C"? "call":"jump") + ")";
        }
        fd.children[fd.children.length] = xrefs;
      }
      fcn_data[fcn_data.length] = fd;
    }
  }
  $('#imports').tree({data: [],selectable: false,slide: false,useContextMenu: false, autoEscape: false});
  $('#functions').tree({data: [],selectable: false,slide: false,useContextMenu: false, autoEscape: false});
  $('#imports').tree('loadData', imp_data);
  $('#functions').tree('loadData', fcn_data);
}
function render_symbols(symbols) {
  var data = [];
  for (var i in symbols) {
    var s = symbols[i];
    var sd = {
      label: "<span class='symbol addr addr_" + "0x" + s.addr.toString(16) + "'>" + s.name + "</span>",
      children: [ {label: "offset: " + "0x" + s.addr.toString(16)}, {label: "size: " + s.size} ] };
    data[data.length] = sd;
  }
  $('#symbols').tree({data: data,selectable: false,slide: false,useContextMenu: false, autoEscape: false});
}
function render_relocs(relocs) {
  var data = [];
  for (var i in relocs) {
    var r = relocs[i];
    var rd = {
      label: "<span class='reloc addr addr_" + "0x" + r.vaddr.toString(16) + "'>" + r.name + "</span>",
      children: [ {label: "offset: " + "0x" + r.vaddr.toString(16)}, {label: "type: " + r.type} ] };
    data[data.length] = rd;
  }
  $('#relocs').tree({data: [],selectable: false,slide: false,useContextMenu: false, autoEscape: false});
  $('#relocs').tree('loadData', data);
}
function render_flags(flags) {
  var data = [];
  for (var i in flags) {
    var f = flags[i];
    var fd = {
      label: "<span class='reloc addr addr_" + "0x" + f.offset.toString(16) + "'>" + f.name + "</span>",
      children: [ {label: "offset: " + "0x" + f.offset.toString(16)}, {label: "size: " + f.size} ] };
    data[data.length] = fd;
  }
  $('#flags').tree({data: [],selectable: false,slide: false,useContextMenu: false, autoEscape: false});
  $('#flags').tree('loadData', data);
}
function render_strings(strings) {
  var data = [];
  for (var i in strings) {
    var f = strings[i];
    var fd = {
      label: f.string,
      children: [
        {label: "vaddr: " + "0x" + f.vaddr.toString(16)},
        {label: "paddr: " + "0x" + f.paddr.toString(16)},
        {label: "length: " + f.length},
        {label: "type: " + f.type}
      ]
    };
    data[data.length] = fd;
  }
  $('#strings').tree({data: [],selectable: false,slide: false,useContextMenu: false});
  $('#strings').tree('loadData', data);
}
function render_sections(sections) {
  var data = [];
  for (var i in sections) {
    var f = sections[i];
    var fd = {
      label: "0x" + f.addr.toString(16) + ": " + f.name,
      children: [
        {label: "vaddr: " + "0x" + f.vaddr.toString(16)},
        {label: "paddr: " + "0x" + f.paddr.toString(16)},
        {label: "flags: " + f.flags},
        {label: "size: " + f.size},
        {label: "vsize: " + f.vsize}
      ]
    };
    data[data.length] = fd;
  }
  $('#sections').tree({data: [],selectable: false,slide: false,useContextMenu: false});
  $('#sections').tree('loadData', data);
}
function render_history(){
  var html = "<div>";
  for (var i in r2ui.history) {
    if (i > r2ui.history_idx - 10 && i < r2ui.history_idx + 5) {
      if (i == r2ui.history_idx - 1) html += "&gt;  <span class='history_idx'>" + r2ui.history[i] + "</span>";
      else html += "&gt; " + r2ui.history[i];
    }
  }
  html += "</div>";
  $('#history').html(html);

}
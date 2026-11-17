// Ticking a range of alerts on the alert list: ace3's manage_alerts.js since 5fb36276. Shift+click on a
// row's box sets every row from the last one clicked to this one to this one's new state, and pressing
// on a box and dragging over other rows sets the rows between to the first box's new state, putting back
// the rows the pointer leaves again. Shift+Space on a focused box is a shift+click, so the keyboard
// ticks a range too.
//
// The ticked rows are Datastar's $_sel on #alert-page (templates/alerts.html), which each box's
// data-effect follows, so this changes no box itself: it sends the page one ace-select event naming the
// ids to tick and to untick, and the page's data-on:ace-select folds them into $_sel. The handlers are
// on the document and find rows by id each time, because the list's refresh morphs the table under
// them: a range reaches only rows that are there now, and one whose other end has gone does nothing.
(function () {
  "use strict";
  var page = document.getElementById("alert-page");
  if (!page) {
    return;
  }
  var BOXES = '#alert-list input[type="checkbox"][name="alert"]';
  var anchor = null; // the id of the row last clicked or dragged to
  var drag = null; // { start, state, original, over, moved } while the button is down on a box
  var dragEnded = false;

  function boxes() {
    return Array.prototype.slice.call(document.querySelectorAll(BOXES));
  }

  function isBox(target) {
    return target instanceof Element && target.matches(BOXES);
  }

  // Sets the rows from id `from` to id `to` to `state`, and the others to how `original` has them
  // when it's given.
  function setRange(from, to, state, original) {
    var all = boxes();
    var ids = all.map(function (box) {
      return box.value;
    });
    var i = ids.indexOf(from);
    var j = ids.indexOf(to);
    if (i === -1 || j === -1) {
      return;
    }
    var on = [];
    var off = [];
    ids.forEach(function (id, k) {
      var wanted;
      if (k >= Math.min(i, j) && k <= Math.max(i, j)) {
        wanted = state;
      } else if (original && Object.prototype.hasOwnProperty.call(original, id)) {
        wanted = original[id];
      } else {
        return;
      }
      (wanted ? on : off).push(id);
    });
    page.dispatchEvent(new CustomEvent("ace-select", { detail: { on: on, off: off } }));
  }

  document.addEventListener("mousedown", function (evt) {
    if (evt.button !== 0 || !isBox(evt.target)) {
      return;
    }
    // Stops a shift+click or a drag from selecting the rows' text. It also stops the box taking the
    // focus, which the keyboard carries on from, so the box is given it here.
    evt.preventDefault();
    evt.target.focus({ preventScroll: true });
    if (!evt.shiftKey) {
      var original = {};
      boxes().forEach(function (box) {
        original[box.value] = box.checked;
      });
      drag = {
        start: evt.target.value,
        state: !evt.target.checked,
        original: original,
        over: evt.target.value,
        moved: false,
      };
    }
  });

  document.addEventListener("mousemove", function (evt) {
    if (!drag) {
      return;
    }
    if (!(evt.buttons & 1)) {
      // released outside the window
      drag = null;
      return;
    }
    var row = evt.target instanceof Element ? evt.target.closest("tr") : null;
    var box = row ? row.querySelector(BOXES) : null;
    if (!box || box.value === drag.over) {
      return;
    }
    drag.over = box.value;
    drag.moved = true;
    setRange(drag.start, box.value, drag.state, drag.original);
    anchor = box.value;
  });

  document.addEventListener("mouseup", function () {
    if (drag && drag.moved) {
      // a release back on the first box clicks it, which would undo the drag there
      dragEnded = true;
      setTimeout(function () {
        dragEnded = false;
      });
    }
    drag = null;
  });

  document.addEventListener("click", function (evt) {
    var box = evt.target;
    if (!isBox(box)) {
      return;
    }
    if (dragEnded) {
      evt.preventDefault();
      return;
    }
    if (evt.shiftKey && anchor !== null && anchor !== box.value) {
      // the range holds this box too, so $_sel has it before its own change event says the same
      setRange(anchor, box.value, box.checked);
    }
    anchor = box.value;
  });
})();

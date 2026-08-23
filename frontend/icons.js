/* РЕСКА — набор SVG-иконок в стиле МЧС РФ.
   Линейные пиктограммы 24x24, currentColor (наследуют цвет текста).
   Использование: icon('home') -> строка <svg>. */
(function () {
  const P = {
    home: '<path d="M3 11l9-8 9 8"/><path d="M5 10v10a1 1 0 001 1h12a1 1 0 001-1V10"/>',
    video: '<rect x="3" y="6" width="18" height="12" rx="2"/><path d="M10 9l5 3-5 3z" fill="currentColor" stroke="none"/>',
    clip: '<rect x="6" y="3" width="12" height="18" rx="2"/><path d="M10 8l4 4-4 4z" fill="currentColor" stroke="none"/>',
    chat: '<path d="M4 5h16a1 1 0 011 1v9a1 1 0 01-1 1H9l-4 4v-4H4a1 1 0 01-1-1V6a1 1 0 011-1z"/>',
    bell: '<path d="M6 9a6 6 0 0112 0c0 4 1 5 2 6H4c1-1 2-2 2-6z"/><path d="M10 19a2 2 0 004 0"/>',
    friends: '<circle cx="9" cy="8" r="3"/><circle cx="17" cy="9" r="2.5"/><path d="M3 20a6 6 0 0112 0"/><path d="M15 20a5 5 0 016-4"/>',
    group: '<circle cx="8" cy="8" r="3"/><circle cx="16" cy="8" r="3"/><path d="M2 20a6 6 0 0112 0"/><path d="M10 20a6 6 0 0112 0"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/>',
    notes: '<path d="M6 3h9l4 4v14a1 1 0 01-1 1H6a1 1 0 01-1-1V4a1 1 0 011-1z"/><path d="M9 9h7M9 13h7M9 17h5"/>',
    star: '<path d="M12 3l2.7 5.5 6 .9-4.3 4.2 1 6-5.4-2.8L6.6 19.6l1-6L3.3 9.4l6-.9z" fill="currentColor" stroke="none"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    heart: '<path d="M12 21C5 14 3 11 3 8.5A4.5 4.5 0 0112 6a4.5 4.5 0 019 2.5C21 11 19 14 12 21z" fill="currentColor" stroke="none"/>',
    heart_o: '<path d="M12 21C5 14 3 11 3 8.5A4.5 4.5 0 0112 6a4.5 4.5 0 019 2.5C21 11 19 14 12 21z"/>',
    smile: '<circle cx="12" cy="12" r="9"/><circle cx="9" cy="10" r="1" fill="currentColor" stroke="none"/><circle cx="15" cy="10" r="1" fill="currentColor" stroke="none"/><path d="M8 15a5 5 0 008 0"/>',
    comment: '<path d="M4 5h16a1 1 0 011 1v8a1 1 0 01-1 1H10l-4 4v-4H4a1 1 0 01-1-1V6a1 1 0 011-1z"/>',
    repost: '<path d="M4 9l3-3 3 3M7 6v9a2 2 0 002 2h8M20 15l-3 3-3-3M17 18V9a2 2 0 00-2-2H7"/>',
    share: '<path d="M12 3v12M8 7l4-4 4 4M8 17l4 4 4-4"/>',
    send: '<path d="M3 11l18-8-8 18-2-7-8-3z" fill="currentColor" stroke="none"/>',
    phone: '<path d="M5 4h3l2 5-2 2a12 12 0 005 5l2-2 5 2v3a2 2 0 01-2 2A16 16 0 013 6a2 2 0 012-2z"/>',
    camera: '<path d="M4 7h3l2-2h6l2 2h3a1 1 0 011 1v11a1 1 0 01-1 1H4a1 1 0 01-1-1V8a1 1 0 011-1z"/><circle cx="12" cy="13" r="3.5"/>',
    shield: '<path d="M12 3l8 3v6c0 5-4 8-8 9-4-1-8-4-8-9V6z"/>',
    logout: '<path d="M14 4h-4a1 1 0 00-1 1v15a1 1 0 001 1h4M10 12h9M16 8l4 4-4 4"/>',
    menu: '<path d="M4 7h16M4 12h16M4 17h16"/>',
    close: '<path d="M6 6l12 12M18 6L6 18"/>',
    check: '<path d="M5 13l4 4L19 7"/>',
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 20a8 8 0 0116 0"/>',
    alert: '<path d="M12 3l10 18H2z"/><path d="M12 9v5M12 17v.5"/>',
    fire: '<path d="M12 3c1 3-2 4-2 7a2 2 0 004 0c0-1 0-2 0-2 2 2 3 4 3 6a5 5 0 11-10 0c0-4 3-6 5-11z"/>',
    call_video: '<path d="M5 4h3l2 5-2 2a12 12 0 005 5l2-2 5 2v3a2 2 0 01-2 2A16 16 0 013 6a2 2 0 012-2z"/><rect x="2" y="5" width="8" height="6" rx="1" fill="currentColor" stroke="none"/>',
    chevron: '<path d="M9 6l6 6-6 6"/>',
    bolt: '<path d="M13 3L4 14h7l-1 7 9-11h-7z" fill="currentColor" stroke="none"/>',
    eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    play: '<path d="M8 5v14l11-7z" fill="currentColor" stroke="none"/>',
    fire: '<path d="M12 3c1 3-2 4-2 7a2 2 0 004 0c0-1 0-2 0-2 2 2 3 4 3 6a5 5 0 11-10 0c0-4 3-6 5-11z"/>',
    settings: '<circle cx="12" cy="12" r="3.2"/><path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M5.6 18.4l1.4-1.4M17 7l1.4-1.4"/>',
    mic: '<rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5 11a7 7 0 0014 0M12 18v3"/>',
    mic_off: '<rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5 11a7 7 0 0014 0M12 18v3M3 3l18 18"/>',
    cam_off: '<path d="M4 7h3l2-2h6l2 2h3v11"/><path d="M3 3l18 18"/>',
    endcall: '<path d="M5 4h3l2 5-2 2a12 12 0 005 5l2-2 5 2v3a2 2 0 01-2 2A16 16 0 013 6a2 2 0 012-2z" transform="rotate(135 12 12)"/>'
  };

  function icon(name, cls) {
    const inner = P[name] || P.alert;
    return (
      '<svg class="ico ico-' + name + (cls ? ' ' + cls : '') + '" viewBox="0 0 24 24" ' +
      'fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      inner + '</svg>'
    );
  }

  window.icon = icon;
})();

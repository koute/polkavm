SECTIONS {
    .heap_size (INFO) : { *(.heap_size) }
    /DISCARD/ : { *(.polkavm_exports .eh_frame .symtab .debug_loc .debug_abbrev .debug_info .debug_aranges .debug_ranges .debug_str .debug_pubnames .debug_pubtypes .debug_line .debug_frame) }
}

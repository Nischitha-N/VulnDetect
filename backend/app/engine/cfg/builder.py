"""
Control-Flow Graph Builder for Tree-sitter C/C++ AST.
Constructs basic blocks and connects control edges for linear statements,
branches (if/else), loops (for/while/do-while), switches, breaks, continues, returns, and gotos.
"""

from typing import List, Dict, Optional, Tuple, Any
from tree_sitter import Node

from app.engine.cfg.graph import ControlFlowGraph, BasicBlock, CFGEdge, EdgeKind
from app.engine.parser import get_node_text, find_nodes_by_type


class LoopContext:
    """Tracks break and continue targets for nested loops."""
    def __init__(self, break_target: BasicBlock, continue_target: BasicBlock):
        self.break_target: BasicBlock = break_target
        self.continue_target: BasicBlock = continue_target


class SwitchContext:
    """Tracks break target for switch statements."""
    def __init__(self, break_target: BasicBlock):
        self.break_target: BasicBlock = break_target


class CFGBuilder:
    """Constructs a ControlFlowGraph from a Tree-sitter function definition node."""

    def __init__(self, func_node: Node, source_code: str):
        self.func_node: Node = func_node
        self.source_code: str = source_code
        self.cfg: ControlFlowGraph = ControlFlowGraph(self._extract_func_name(func_node), func_node)
        self.loop_stack: List[LoopContext] = []
        self.switch_stack: List[SwitchContext] = []
        self.label_blocks: Dict[str, BasicBlock] = {}
        self.pending_gotos: List[Tuple[BasicBlock, str]] = []

    @staticmethod
    def _extract_func_name(func_node: Node) -> str:
        decl = func_node.child_by_field_name("declarator")
        if not decl:
            return "anonymous_function"
        # Dig down declarator chain
        curr = decl
        while curr and curr.type in ("function_declarator", "pointer_declarator"):
            child = curr.child_by_field_name("declarator")
            if child:
                curr = child
            else:
                break
        return curr.text.decode("utf-8", errors="replace") if curr and curr.text else "function"

    def build(self) -> ControlFlowGraph:
        """Construct the complete CFG for the function."""
        # 1. Create Entry and Exit basic blocks
        entry = self.cfg.new_block("Entry")
        entry.is_entry = True
        self.cfg.entry_block = entry

        exit_block = self.cfg.new_block("Exit")
        exit_block.is_exit = True
        self.cfg.exit_block = exit_block

        # 2. First pass: Pre-scan labels for goto resolution
        self._prescan_labels()

        # 3. Process function body
        body = self.func_node.child_by_field_name("body")
        if body:
            last_block = self._build_statement(body, entry)
            # If the last block didn't unconditionally terminate, connect to Exit
            if last_block and not self._is_block_terminated(last_block):
                self.cfg.add_edge(last_block, exit_block, EdgeKind.FALLTHROUGH)
        else:
            self.cfg.add_edge(entry, exit_block, EdgeKind.FALLTHROUGH)

        # 4. Resolve pending gotos
        for src_block, label_name in self.pending_gotos:
            if label_name in self.label_blocks:
                target_block = self.label_blocks[label_name]
                self.cfg.add_edge(src_block, target_block, EdgeKind.GOTO_TARGET, label=f"goto {label_name}")

        return self.cfg

    def _prescan_labels(self):
        """Find all labeled statements and allocate their basic blocks ahead of time."""
        labeled_nodes = find_nodes_by_type(self.func_node, ["labeled_statement"])
        for node in labeled_nodes:
            lbl_child = node.child_by_field_name("label")
            if lbl_child:
                lbl_name = get_node_text(lbl_child, self.source_code).strip()
                if lbl_name and lbl_name not in self.label_blocks:
                    block = self.cfg.new_block(f"Label_{lbl_name}")
                    self.label_blocks[lbl_name] = block

    def _is_block_terminated(self, block: BasicBlock) -> bool:
        """Returns true if block ends with an unconditional jump (return, break, goto)."""
        return any(
            e.kind in (EdgeKind.RETURN_TO_EXIT, EdgeKind.BREAK_TO_EXIT, EdgeKind.GOTO_TARGET)
            for e in block.outgoing_edges
        )

    def _build_statement(self, node: Node, current_block: BasicBlock) -> Optional[BasicBlock]:
        """
        Recursively translates a statement AST node into basic blocks and returns
        the active outgoing block.
        """
        if not node:
            return current_block

        ntype = node.type

        # 1. Compound statement { s1; s2; ... }
        if ntype == "compound_statement":
            curr = current_block
            for child in node.named_children:
                curr = self._build_statement(child, curr)
                if not curr:
                    break
            return curr

        # 2. Sequential statements / declarations / expressions
        elif ntype in ("declaration", "expression_statement"):
            current_block.add_statement(node)
            return current_block

        # 3. Labeled Statement (label: stmt)
        elif ntype == "labeled_statement":
            lbl_child = node.child_by_field_name("label")
            stmt_child = node.child_by_field_name("statement")
            lbl_name = get_node_text(lbl_child, self.source_code).strip() if lbl_child else ""
            target_block = self.label_blocks.get(lbl_name, self.cfg.new_block(f"Label_{lbl_name}"))

            if not self._is_block_terminated(current_block):
                self.cfg.add_edge(current_block, target_block, EdgeKind.FALLTHROUGH)

            if stmt_child:
                return self._build_statement(stmt_child, target_block)
            return target_block

        # 4. If Statement (if (cond) then_stmt else else_stmt)
        elif ntype == "if_statement":
            return self._build_if_statement(node, current_block)

        # 5. While Statement (while (cond) body)
        elif ntype == "while_statement":
            return self._build_while_statement(node, current_block)

        # 6. Do-While Statement (do body while (cond))
        elif ntype == "do_statement":
            return self._build_do_statement(node, current_block)

        # 7. For Statement (for (init; cond; update) body)
        elif ntype == "for_statement":
            return self._build_for_statement(node, current_block)

        # 8. Switch Statement (switch (expr) { case ... })
        elif ntype == "switch_statement":
            return self._build_switch_statement(node, current_block)

        # 9. Return Statement
        elif ntype == "return_statement":
            current_block.add_statement(node)
            current_block.set_terminator(node)
            self.cfg.add_edge(current_block, self.cfg.exit_block, EdgeKind.RETURN_TO_EXIT)
            return None  # Unreachable continuation

        # 10. Break Statement
        elif ntype == "break_statement":
            current_block.add_statement(node)
            current_block.set_terminator(node)
            target = None
            if self.switch_stack:
                target = self.switch_stack[-1].break_target
            elif self.loop_stack:
                target = self.loop_stack[-1].break_target
            if target:
                self.cfg.add_edge(current_block, target, EdgeKind.BREAK_TO_EXIT)
            return None

        # 11. Continue Statement
        elif ntype == "continue_statement":
            current_block.add_statement(node)
            current_block.set_terminator(node)
            if self.loop_stack:
                target = self.loop_stack[-1].continue_target
                self.cfg.add_edge(current_block, target, EdgeKind.CONTINUE_LOOP)
            return None

        # 12. Goto Statement (goto label;)
        elif ntype == "goto_statement":
            current_block.add_statement(node)
            current_block.set_terminator(node)
            lbl_child = node.child_by_field_name("label") or (node.named_children[0] if node.named_children else None)
            lbl_name = get_node_text(lbl_child, self.source_code).strip() if lbl_child else ""
            if lbl_name:
                self.pending_gotos.append((current_block, lbl_name))
            return None

        # Default fallback
        current_block.add_statement(node)
        return current_block

    def _build_if_statement(self, node: Node, current_block: BasicBlock) -> Optional[BasicBlock]:
        cond_node = node.child_by_field_name("condition")
        then_node = node.child_by_field_name("consequence")
        else_node = node.child_by_field_name("alternative")

        cond_block = current_block
        if cond_node:
            cond_block.set_terminator(cond_node)

        then_block = self.cfg.new_block("IfThen")
        else_block = self.cfg.new_block("IfElse") if else_node else None
        merge_block = self.cfg.new_block("IfMerge")

        # True branch edge
        self.cfg.add_edge(cond_block, then_block, EdgeKind.TRUE_BRANCH, condition_node=cond_node)

        # False branch edge
        if else_block:
            self.cfg.add_edge(cond_block, else_block, EdgeKind.FALSE_BRANCH, condition_node=cond_node)
        else:
            self.cfg.add_edge(cond_block, merge_block, EdgeKind.FALSE_BRANCH, condition_node=cond_node)

        # Build Then body
        then_end = self._build_statement(then_node, then_block)
        if then_end and not self._is_block_terminated(then_end):
            self.cfg.add_edge(then_end, merge_block, EdgeKind.FALLTHROUGH)

        # Build Else body if present
        if else_block and else_node:
            else_end = self._build_statement(else_node, else_block)
            if else_end and not self._is_block_terminated(else_end):
                self.cfg.add_edge(else_end, merge_block, EdgeKind.FALLTHROUGH)

        # If merge block has no incoming edges, it is unreachable
        if not merge_block.incoming_edges:
            return None
        return merge_block

    def _build_while_statement(self, node: Node, current_block: BasicBlock) -> BasicBlock:
        cond_node = node.child_by_field_name("condition")
        body_node = node.child_by_field_name("body")

        cond_block = self.cfg.new_block("WhileCond")
        body_block = self.cfg.new_block("WhileBody")
        merge_block = self.cfg.new_block("WhileMerge")

        self.cfg.add_edge(current_block, cond_block, EdgeKind.FALLTHROUGH)

        # Setup loop context for break / continue
        self.loop_stack.append(LoopContext(break_target=merge_block, continue_target=cond_block))

        if cond_node:
            cond_block.set_terminator(cond_node)
            self.cfg.add_edge(cond_block, body_block, EdgeKind.LOOP_BODY, condition_node=cond_node)
            self.cfg.add_edge(cond_block, merge_block, EdgeKind.LOOP_EXIT, condition_node=cond_node)
        else:
            self.cfg.add_edge(cond_block, body_block, EdgeKind.LOOP_BODY)

        # Build body
        body_end = self._build_statement(body_node, body_block)
        if body_end and not self._is_block_terminated(body_end):
            self.cfg.add_edge(body_end, cond_block, EdgeKind.LOOP_BACK)

        self.loop_stack.pop()
        return merge_block

    def _build_do_statement(self, node: Node, current_block: BasicBlock) -> BasicBlock:
        body_node = node.child_by_field_name("body")
        cond_node = node.child_by_field_name("condition")

        body_block = self.cfg.new_block("DoBody")
        cond_block = self.cfg.new_block("DoCond")
        merge_block = self.cfg.new_block("DoMerge")

        self.cfg.add_edge(current_block, body_block, EdgeKind.FALLTHROUGH)

        self.loop_stack.append(LoopContext(break_target=merge_block, continue_target=cond_block))

        body_end = self._build_statement(body_node, body_block)
        if body_end and not self._is_block_terminated(body_end):
            self.cfg.add_edge(body_end, cond_block, EdgeKind.FALLTHROUGH)

        if cond_node:
            cond_block.set_terminator(cond_node)
            self.cfg.add_edge(cond_block, body_block, EdgeKind.TRUE_BRANCH, condition_node=cond_node)
            self.cfg.add_edge(cond_block, merge_block, EdgeKind.FALSE_BRANCH, condition_node=cond_node)
        else:
            self.cfg.add_edge(cond_block, merge_block, EdgeKind.FALLTHROUGH)

        self.loop_stack.pop()
        return merge_block

    def _build_for_statement(self, node: Node, current_block: BasicBlock) -> BasicBlock:
        init_node = node.child_by_field_name("initializer")
        cond_node = node.child_by_field_name("condition")
        update_node = node.child_by_field_name("update")
        body_node = node.child_by_field_name("body")

        init_block = current_block
        if init_node:
            init_block.add_statement(init_node)

        cond_block = self.cfg.new_block("ForCond")
        body_block = self.cfg.new_block("ForBody")
        update_block = self.cfg.new_block("ForUpdate")
        merge_block = self.cfg.new_block("ForMerge")

        self.cfg.add_edge(init_block, cond_block, EdgeKind.FALLTHROUGH)

        self.loop_stack.append(LoopContext(break_target=merge_block, continue_target=update_block))

        if cond_node:
            cond_block.set_terminator(cond_node)
            self.cfg.add_edge(cond_block, body_block, EdgeKind.LOOP_BODY, condition_node=cond_node)
            self.cfg.add_edge(cond_block, merge_block, EdgeKind.LOOP_EXIT, condition_node=cond_node)
        else:
            self.cfg.add_edge(cond_block, body_block, EdgeKind.LOOP_BODY)

        # Body
        body_end = self._build_statement(body_node, body_block)
        if body_end and not self._is_block_terminated(body_end):
            self.cfg.add_edge(body_end, update_block, EdgeKind.FALLTHROUGH)

        if update_node:
            update_block.add_statement(update_node)
        self.cfg.add_edge(update_block, cond_block, EdgeKind.LOOP_BACK)

        self.loop_stack.pop()
        return merge_block

    def _build_switch_statement(self, node: Node, current_block: BasicBlock) -> BasicBlock:
        cond_node = node.child_by_field_name("condition")
        body_node = node.child_by_field_name("body")

        switch_header = current_block
        if cond_node:
            switch_header.set_terminator(cond_node)

        merge_block = self.cfg.new_block("SwitchMerge")
        self.switch_stack.append(SwitchContext(break_target=merge_block))

        # Dig cases inside body
        if body_node and body_node.type == "compound_statement":
            curr_case_block = None
            for child in body_node.named_children:
                if child.type in ("case_statement", "labeled_statement"):
                    val_node = child.child_by_field_name("value")
                    val_text = get_node_text(val_node, self.source_code).strip() if val_node else "default"
                    is_default = (val_text == "default" or child.type == "case_statement" and not val_node)

                    case_block = self.cfg.new_block(f"Case_{val_text}")
                    edge_kind = EdgeKind.DEFAULT_CASE if is_default else EdgeKind.SWITCH_CASE
                    self.cfg.add_edge(switch_header, case_block, edge_kind, case_value=val_text)

                    # Fallthrough from previous case
                    if curr_case_block and not self._is_block_terminated(curr_case_block):
                        self.cfg.add_edge(curr_case_block, case_block, EdgeKind.FALLTHROUGH)

                    curr_case_block = self._build_statement(child, case_block)
                else:
                    if curr_case_block:
                        curr_case_block = self._build_statement(child, curr_case_block)
                    else:
                        case_block = self.cfg.new_block("SwitchBody")
                        self.cfg.add_edge(switch_header, case_block, EdgeKind.FALLTHROUGH)
                        curr_case_block = self._build_statement(child, case_block)

            if curr_case_block and not self._is_block_terminated(curr_case_block):
                self.cfg.add_edge(curr_case_block, merge_block, EdgeKind.FALLTHROUGH)
        else:
            self.cfg.add_edge(switch_header, merge_block, EdgeKind.FALLTHROUGH)

        self.switch_stack.pop()
        return merge_block

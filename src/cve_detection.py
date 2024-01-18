#!/usr/bin/env python3
import re
from abc import ABC, abstractmethod
from pathlib import Path

from code_analysis import AST, ASTReader

WP_AST_DIR = Path(__file__).parent / ".." / "code_to_analyze/wordpress_ast"


class AbstractVisitor(ABC):
    def __init__(self):
        self.ast = None

    def visit(self, ast: AST):
        self.ast = ast
        self._visit(self.ast.get_root())

    @abstractmethod
    def _visit(self, node_id: int):
        ...


class AST_2017_7189_Visitor(AbstractVisitor):
    def _visit(self, node_id: int):
        children = self.ast.get_children(node_id)

        if (
            len(children) > 1
            and self.ast.get_type(node_id) == "FunctionCall"
            and self.ast.get_image(node_id) == "fsockopen"
            and self.ast.get_type(children[1]) == "ArgumentList"
        ):
            params = self.ast.get_children(children[1])
            if len(params) > 0 and (
                self.ast.get_type(params[0]) != "StringExpression"
                or re.search(r"^\$|:\d+$", self.ast.get_image(params[0]))
            ):
                print(
                    f"Potential CVE-2017-7189 detected, file "
                    f'"{(WP_AST_DIR / self.ast.get_filename()).resolve()}", line {self.ast.get_position(node_id)[0]}'
                )

        for child_id in children:
            self._visit(child_id)


class AST_2021_21707_Visitor(AbstractVisitor):
    def _visit(self, node_id: int):
        children = self.ast.get_children(node_id)

        if (
            len(children) >= 2
            and self.ast.get_type(node_id) == "FunctionCall"
            and self.ast.get_image(node_id) == "simplexml_load_file"
        ):
            print(
                f"Potential CVE-2021-21707 detected, file "
                f'"{(WP_AST_DIR / self.ast.get_filename()).resolve()}", line {self.ast.get_position(node_id)[0]}'
            )

        for child_id in children:
            self._visit(child_id)


class AST_2019_9025_Visitor(AbstractVisitor):
    def _visit(self, node_id: int):
        children = self.ast.get_children(node_id)

        if (
            len(children) >= 2
            and self.ast.get_type(node_id) == "FunctionCall"
            and self.ast.get_image(node_id) == "mb_split"
        ):
            params = self.ast.get_children(children[1])
            # TODO: Check that the multibyte string is illegal
            print(
                f"Potential CVE-2019-9025 detected, file "
                f'"{(WP_AST_DIR / self.ast.get_filename()).resolve()}", line {self.ast.get_position(node_id)[0]}'
            )

        for child_id in children:
            self._visit(child_id)


visitors = [
    AST_2017_7189_Visitor(),
    AST_2019_9025_Visitor(),
    AST_2021_21707_Visitor(),
]

unit_tests = [
    Path(__file__).parent / ".." / "code_to_analyze/test_cve/2017_7189.php.ast.json",
    Path(__file__).parent / ".." / "code_to_analyze/test_cve/2019_9025.php.ast.json",
    Path(__file__).parent / ".." / "code_to_analyze/test_cve/2021_21707.php.ast.json",
]


def run_on_testfile():
    reader = ASTReader()
    for visitor, file in zip(visitors, unit_tests):
        ast = reader.read_ast(file)
        visitor.visit(ast)


def run_on_wordpress():
    reader = ASTReader()
    for visitor in visitors:
        with (WP_AST_DIR / "filelist").open() as file:
            for line in file:
                ast = reader.read_ast(WP_AST_DIR / line.strip())
                visitor.visit(ast)


if __name__ == "__main__":
    run_on_testfile()
    run_on_wordpress()

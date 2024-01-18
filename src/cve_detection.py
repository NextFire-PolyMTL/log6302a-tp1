#!/usr/bin/env python3
import re
from abc import ABC, abstractmethod
from pathlib import Path

from code_analysis import AST, ASTReader


class AbstractVisitor(ABC):
    def __init__(self):
        self.ast = None

    def visit(self, ast: AST, sources_dir: Path):
        self.ast = ast
        self._visit(self.ast.get_root(), sources_dir)

    @abstractmethod
    def _visit(self, node_id: int, sources_dir: Path):
        ...


class AST_2017_7189_Visitor(AbstractVisitor):
    def _visit(self, node_id: int, sources_dir: Path):
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
                    f'"{(sources_dir / self.ast.get_filename()).resolve()}", line {self.ast.get_position(node_id)[0]}'
                )

        for child_id in children:
            self._visit(child_id, sources_dir)


class AST_2021_21707_Visitor(AbstractVisitor):
    def _visit(self, node_id: int, sources_dir: Path):
        children = self.ast.get_children(node_id)

        if (
            len(children) >= 2
            and self.ast.get_type(node_id) == "FunctionCall"
            and self.ast.get_image(node_id) == "simplexml_load_file"
        ):
            print(
                f"Potential CVE-2021-21707 detected, file "
                f'"{(sources_dir / self.ast.get_filename()).resolve()}", line {self.ast.get_position(node_id)[0]}'
            )

        for child_id in children:
            self._visit(child_id, sources_dir)


class AST_2019_9025_Visitor(AbstractVisitor):
    def _visit(self, node_id: int, sources_dir: Path):
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
                f'"{(sources_dir / self.ast.get_filename()).resolve()}", line {self.ast.get_position(node_id)[0]}'
            )

        for child_id in children:
            self._visit(child_id, sources_dir)


visitors: list[AbstractVisitor] = [
    AST_2017_7189_Visitor(),
    AST_2021_21707_Visitor(),
    AST_2019_9025_Visitor(),
]

UNIT_TESTS_DIR = Path(__file__).parent / ".." / "code_to_analyze/test_cve"

unit_tests = [
    UNIT_TESTS_DIR / "2017_7189.php.ast.json",
    UNIT_TESTS_DIR / "2021_21707.php.ast.json",
    UNIT_TESTS_DIR / "2019_9025.php.ast.json",
]


def run_on_testfile():
    reader = ASTReader()
    for visitor, file in zip(visitors, unit_tests):
        ast = reader.read_ast(file)
        visitor.visit(ast, UNIT_TESTS_DIR / "..")


WP_AST_DIR = Path(__file__).parent / ".." / "code_to_analyze/wordpress_ast"
WP_SOURCES_DIR = Path(__file__).parent / ".." / "code_to_analyze/wordpress_sources"


def run_on_wordpress():
    reader = ASTReader()
    for visitor in visitors:
        with (WP_AST_DIR / "filelist").open() as file:
            for line in file:
                ast = reader.read_ast(WP_AST_DIR / line.strip())
                visitor.visit(ast, WP_SOURCES_DIR)


if __name__ == "__main__":
    run_on_testfile()
    run_on_wordpress()

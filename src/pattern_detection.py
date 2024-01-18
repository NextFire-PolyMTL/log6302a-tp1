#!/usr/bin/env python3
from pathlib import Path

from code_analysis import AST, ASTReader

AST_DIR = Path(__file__).parent / "../code_to_analyze/wordpress_ast"


class ASTQueryVisitor:
    def __init__(self):
        self.ast = None

    def visit(self, ast: AST):
        self.ast = ast
        self.__visit(self.ast.get_root())

    def __visit(self, node_id: int):
        if self.ast.get_type(node_id) == "FunctionCall":
            image = self.ast.get_image(node_id)
            if image in ["mysql_query", "mysqli_query"]:
                print(
                    f"Database call '{image}' in line {self.ast.get_position(node_id)[0]}"
                )

        if (
            self.ast.get_type(node_id) == "BinOP"
            and self.ast.get_image(node_id) == "->"
        ):
            children = self.ast.get_children(node_id)
            if (
                len(children) > 1
                and self.ast.get_type(children[0]) == "Variable"
                and self.ast.get_type(children[1]) == "MethodCall"
                and self.ast.get_image(children[1]) == "execute"
            ):
                print(
                    f"Database call '{self.ast.get_image(children[0])}->{self.ast.get_image(children[1])}' "
                    f"in line {self.ast.get_position(node_id)[0]}"
                )

            if (
                len(children) > 1
                and self.ast.get_type(children[0]) == "BinOP"
                and self.ast.get_type(children[1]) == "MethodCall"
                and self.ast.get_image(children[1]) == "exec"
            ):
                binop_children = self.ast.get_children(children[0])
                if (
                    len(binop_children) > 1
                    and self.ast.get_image(binop_children[1]) == "mysql"
                ):
                    print(
                        f"Database call '{self.ast.get_image(binop_children[0])}->{self.ast.get_image(binop_children[1])}->{self.ast.get_image(children[1])}' "
                        f"in line {self.ast.get_position(node_id)[0]}"
                    )

        for child_id in self.ast.get_children(node_id):
            self.__visit(child_id)


def main():
    reader = ASTReader()
    visitor = ASTQueryVisitor()
    with (AST_DIR / "filelist").open() as file:
        for line in file:
            ast = reader.read_ast(AST_DIR / line.strip())
            visitor.visit(ast)


if __name__ == "__main__":
    main()

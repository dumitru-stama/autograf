#[derive(Debug)]
pub struct TreePool<T> {
    nodes: Vec<Node<T>>
}

impl<T> TreePool<T> {
    pub fn new() -> TreePool<T> {
        TreePool {
            nodes: vec![]
        }
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.len() == 0
    }

    pub fn size(&self) -> usize {
        self.nodes.len()
    }

    pub fn how_many_roots(&self) -> usize {
        let mut roots = 0;
        for i in 0..self.nodes.len() {
            if let None = self.nodes[i].parent{
                roots += 1;
            }
        }
        roots
    }

    pub fn get_nth(&self, nth: usize) -> Option<&Node<T>> {
        if nth >= self.nodes.len() {
            return None;
        }
        Some(&self.nodes[nth])
    }

    pub fn get_children(&self, node: &Node<T>) -> Vec<&Node<T>> {
        let mut child = node.first_child;
        let mut children: Vec<&Node<T>> = vec![];
        if let None = child {
            return children;
        }

        loop {
            match child {
                Some(c) => children.push(&self.nodes[c]),
                None => break
            }
            child = self.nodes[child.unwrap()].next_sibling;
        }

        children
    }

    pub fn get_next_sibling(&self, nth: usize) -> Result< &Node<T>, String > {
        if nth >= self.nodes.len() {
            return Err(format!("[TreePool::get_next_sibling] nth larger than vector size: {} >= {}", nth, self.nodes.len()));
        }

        match self.nodes[nth].next_sibling {
            Some(nsib) => return Ok(&self.nodes[nsib]),
            None => return Err(format!("[TreePool::get_next_sibling] Node {} has no next sibling", nth))
        }
    }

    pub fn get_prev_sibling(&self, nth: usize) -> Result< &Node<T>, String > {
        if nth >= self.nodes.len() {
            return Err(format!("[TreePool::get_prev_sibling] nth larger than vector size: {} >= {}", nth, self.nodes.len()));
        }

        match self.nodes[nth].prev_sibling {
            Some(psib) => return Ok(&self.nodes[psib]),
            None => return Err(format!("[TreePool::get_prev_sibling] Node {} has no prev sibling", nth))
        }
    }


    pub fn add_node(&mut self, parent: Option<usize>, val: T) -> Result<usize, String> {
        let index = self.nodes.len();
        
        let mut child = Node::new(val);
        child.parent = parent;
        child.index = index;
        self.nodes.push(child);
       
        if let Some(p) = parent {
            match self.nodes[p].last_child {
                Some(idx) => match self.nodes[p].first_child {
                    None => {
                        self.nodes[p].first_child = Some(idx);
                        self.nodes[p].last_child = Some(index);
                        self.nodes[idx].prev_sibling = None;
                        self.nodes[idx].next_sibling = Some(index);
                        self.nodes[index].next_sibling = None;
                        self.nodes[index].prev_sibling = Some(idx);
                    },

                    Some(_) => {
                        self.nodes[idx].next_sibling = Some(index);
                        self.nodes[index].prev_sibling = Some(idx);
                        self.nodes[p].last_child = Some(index);
                    }
                },

                None => match self.nodes[p].first_child {
                    Some(fi) => {
                        self.nodes[p].last_child = Some(index);
                        self.nodes[index].prev_sibling = Some(fi);
                        self.nodes[index].next_sibling = None;
                        self.nodes[fi].next_sibling = Some(index);
                        self.nodes[fi].prev_sibling = None;
                    },

                    None => {
                        self.nodes[p].last_child = Some(index);
                        self.nodes[p].first_child = Some(index);
                        self.nodes[index].next_sibling = None;
                        self.nodes[index].prev_sibling = None;
                    }
                }
            }
        }

        Ok(index as usize)
    }
}

#[derive(Debug)]
pub struct Node<T> {
    pub index: usize,
    pub parent: Option<usize>,
    pub value: Option<T>,
    pub first_child: Option<usize>,
    pub last_child: Option<usize>,
    pub next_sibling: Option<usize>,
    pub prev_sibling: Option<usize>,
    pub offset: usize,
    pub new_offset: usize
}

impl<T> Node<T> {
    pub fn new(val: T) -> Node<T> {
        Node {
            value: Some(val),
            parent: None,
            index: 0,
            first_child: None,
            last_child: None,
            next_sibling: None,
            prev_sibling: None,
            offset: 0,
            new_offset: 0
        }
    }
    
    pub fn get_first_child_index(&self) -> Result<usize, String> {
        match self.first_child {
            Some(fc) => return Ok(fc),
            None => return Err(format!("[Node::get_first_child_index] Node {} has no first child", self.index))
        }
    }
    
    pub fn get_last_child_index(&self) -> Result<usize, String> {
        match self.last_child {
            Some(lc) => return Ok(lc),
            None => return Err(format!("[Node::get_last_child_index] Node {} has no last child", self.index))
        }
    }
}

